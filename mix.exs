#-*-Mode:elixir;coding:utf-8;tab-width:2;c-basic-offset:2;indent-tabs-mode:()-*-
# ex: set ft=elixir fenc=utf-8 sts=2 ts=2 sw=2 et nomod:

defmodule Quickrand.Mixfile do
  use Mix.Project

  def project do
    [app: :quickrand,
     version: "1.7.3",
     language: :erlang,
     description: description(),
     package: package(),
     deps: deps()]
  end

  def application do
    [applications: [
       :crypto]]
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
    [files: ~w(src doc rebar.config README.markdown),
     maintainers: ["Michael Truog"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/okeuday/quickrand"}]
   end
end
