defmodule ChatSvc.MixProject do
  use Mix.Project

  def project do
    [app: :chat_svc, version: "0.1.0", elixir: "~> 1.15", deps: deps()]
  end

  defp deps do
    [
      {:phoenix, "~> 1.7.10"},
      {:plug_cowboy, "~> 2.6"},
      {:jason, "~> 1.4"},
      {:jose, "~> 1.11"}
    ]
  end
end
