// The oracle for crates/clr: every method of each assembly and the ops fleetreach's call
// graph reads, printed in the format of `cargo run -p fleetreach-clr --example clrdump`.
// Metadata comes from System.Reflection.Metadata, and IL is stepped with the operand
// widths of the runtime's own System.Reflection.Emit.OpCodes table, so no code is shared.
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

static class Oracle
{
    static readonly Dictionary<short, OpCode> Codes = new();

    static void Main(string[] args)
    {
        foreach (var f in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
            if (f.GetValue(null) is OpCode op) Codes[op.Value] = op;
        var stdout = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false));
        stdout.NewLine = "\n";
        foreach (var path in args)
        {
            try { Dump(path, stdout); }
            catch (Exception e) { stdout.WriteLine($"E {path} {e.GetType().Name}"); }
        }
        stdout.Flush();
    }

    static void Dump(string path, StreamWriter o)
    {
        using var stream = File.OpenRead(path);
        using var pe = new PEReader(stream);
        if (!pe.HasMetadata) { o.WriteLine($"E {path} no metadata"); return; }
        var md = pe.GetMetadataReader();
        var lines = new List<string>();
        var name = md.IsAssembly ? md.GetString(md.GetAssemblyDefinition().Name) : "";
        lines.Add($"A {path} {name}");
        foreach (var th in md.TypeDefinitions)
        {
            var type = md.GetTypeDefinition(th);
            var typeName = DefName(md, th);
            foreach (var mh in type.GetMethods())
            {
                var m = md.GetMethodDefinition(mh);
                var mname = md.GetString(m.Name);
                bool il = ((int)m.ImplAttributes & 3) == 0;
                if (m.RelativeVirtualAddress == 0 || !il) { lines.Add($"M {typeName}::{mname} -"); continue; }
                var body = pe.GetMethodBody(m.RelativeVirtualAddress);
                var code = body.GetILBytes();
                lines.Add($"M {typeName}::{mname} {code.Length}");
                Ops(md, code, lines);
            }
        }
        foreach (var l in lines) o.WriteLine(l);
    }

    static void Ops(MetadataReader md, byte[] code, List<string> lines)
    {
        int at = 0;
        while (at < code.Length)
        {
            short value = code[at] == 0xFE ? (short)(0xFE00 | code[at + 1]) : code[at];
            var op = Codes[value];
            at += op.Size;
            int len = op.OperandType switch
            {
                OperandType.InlineNone => 0,
                OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                OperandType.InlineVar => 2,
                OperandType.InlineI8 or OperandType.InlineR => 8,
                OperandType.InlineSwitch => 4 + 4 * BitConverter.ToInt32(code, at),
                _ => 4,
            };
            int token = len == 4 ? BitConverter.ToInt32(code, at) : 0;
            string n = op.Name;
            if (n is "call" or "callvirt" or "newobj" or "ldftn" or "ldvirtftn" or "jmp")
                lines.Add($" {n} {Method(md, token)}");
            else if (n == "ldstr")
                lines.Add($" ldstr {md.GetUserString(MetadataTokens.UserStringHandle(token & 0xFFFFFF)).Length}");
            else if (n is "ldsfld" or "ldsflda" or "stsfld")
                lines.Add($" sfld {FieldOwner(md, token)}");
            else if (n == "ldtoken")
            {
                var h = MetadataTokens.EntityHandle(token);
                if (h.Kind is HandleKind.TypeDefinition or HandleKind.TypeReference or HandleKind.TypeSpecification)
                    lines.Add($" ldtoken T {TypeName(md, h)}");
                else if (h.Kind == HandleKind.FieldDefinition ||
                         (h.Kind == HandleKind.MemberReference && md.GetMemberReference((MemberReferenceHandle)h).GetKind() == MemberReferenceKind.Field))
                    lines.Add($" ldtoken F {FieldOwner(md, token)}");
                else
                    lines.Add($" ldtoken M {Method(md, token)}");
            }
            at += len;
        }
    }

    static string FieldOwner(MetadataReader md, int token)
    {
        var h = MetadataTokens.EntityHandle(token);
        if (h.Kind == HandleKind.FieldDefinition)
            return DefName(md, md.GetFieldDefinition((FieldDefinitionHandle)h).GetDeclaringType());
        return Parent(md, md.GetMemberReference((MemberReferenceHandle)h).Parent);
    }

    static string Method(MetadataReader md, int token)
    {
        var h = MetadataTokens.EntityHandle(token);
        switch (h.Kind)
        {
            case HandleKind.MethodDefinition:
                var d = md.GetMethodDefinition((MethodDefinitionHandle)h);
                return $"{DefName(md, d.GetDeclaringType())}::{md.GetString(d.Name)}";
            case HandleKind.MemberReference:
                var r = md.GetMemberReference((MemberReferenceHandle)h);
                return $"{Parent(md, r.Parent)}::{md.GetString(r.Name)}";
            case HandleKind.MethodSpecification:
                return Method(md, MetadataTokens.GetToken(md.GetMethodSpecification((MethodSpecificationHandle)h).Method));
        }
        throw new BadImageFormatException("method token");
    }

    static string Parent(MetadataReader md, EntityHandle p) => p.Kind switch
    {
        HandleKind.ModuleReference => "<module>",
        HandleKind.MethodDefinition => DefName(md, md.GetMethodDefinition((MethodDefinitionHandle)p).GetDeclaringType()),
        _ => TypeName(md, p),
    };

    static string TypeName(MetadataReader md, EntityHandle h)
    {
        switch (h.Kind)
        {
            case HandleKind.TypeDefinition: return DefName(md, (TypeDefinitionHandle)h);
            case HandleKind.TypeReference:
                var r = md.GetTypeReference((TypeReferenceHandle)h);
                var local = Qualified(md.GetString(r.Namespace), md.GetString(r.Name));
                if (r.ResolutionScope.Kind == HandleKind.TypeReference && r.ResolutionScope != h)
                    return $"{TypeName(md, (EntityHandle)r.ResolutionScope)}+{local}";
                return local;
            case HandleKind.TypeSpecification:
                var blob = md.GetBlobReader(md.GetTypeSpecification((TypeSpecificationHandle)h).Signature);
                if (blob.Length >= 2 && blob.ReadByte() == 0x15)
                {
                    var kind = blob.ReadByte();
                    if (kind == 0x11 || kind == 0x12)
                    {
                        var g = blob.ReadTypeHandle();
                        if (g.Kind is HandleKind.TypeDefinition or HandleKind.TypeReference) return TypeName(md, g);
                    }
                }
                return "<spec>";
        }
        throw new BadImageFormatException("type token");
    }

    static string DefName(MetadataReader md, TypeDefinitionHandle h)
    {
        var t = md.GetTypeDefinition(h);
        var local = Qualified(md.GetString(t.Namespace), md.GetString(t.Name));
        var outer = t.GetDeclaringType();
        return outer.IsNil ? local : $"{DefName(md, outer)}+{local}";
    }

    static string Qualified(string ns, string name) => ns.Length == 0 ? name : $"{ns}.{name}";
}
