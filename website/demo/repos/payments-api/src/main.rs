use smallvec::SmallVec;

/// Amounts for one payment, in cents, kept inline for the common small case.
type Amounts = SmallVec<[u64; 8]>;

fn merge(amounts: &mut Amounts, at: usize, extra: &[u64]) {
    amounts.insert_many(at, extra.iter().copied());
}

fn main() {
    let mut amounts = Amounts::new();
    merge(&mut amounts, 0, &[1250, 399]);
    println!("{} amounts", amounts.len());
}
