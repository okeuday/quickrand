defmodule Quickrand.Mixfile do
  use Mix.Project

  def project do
    [app: :quickrand,
     version: "1.4.0-rc.4",
     language: :erlang,
     description: description,
     package: package,
     deps: deps]
  end

  defp deps do
    []
  end

  defp description do
    "Quick Random Number Generation: " <>
    "Provides a simple interface to call efficient random number generation " <>
    "functions based on the context.  Proper random number seeding is enforced."
  end

  defp package do
    [files: ~w(src doc erlang.mk Makefile rebar.config README.markdown),
     contributors: ["Michael Truog"],
     licenses: ["BSD"],
     links: %{"GitHub" => "https://github.com/okeuday/quickrand"}]
   end
end
