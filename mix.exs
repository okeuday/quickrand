#-*-Mode:elixir;coding:utf-8;tab-width:2;c-basic-offset:2;indent-tabs-mode:()-*-
# ex: set ft=elixir fenc=utf-8 sts=2 ts=2 sw=2 et nomod:

defmodule Quickrand.Mixfile do
  use Mix.Project

  def project do
    [app: :quickrand,
     version: "2.0.7",
     language: :erlang,
     erlc_options: [
       {:d, String.to_atom("ERLANG_OTP_VERSION_" <> to_string(System.otp_release()))},
       :deterministic,
       :debug_info,
       :warn_export_vars,
       :warn_unused_import,
       #:warn_missing_spec,
       :warnings_as_errors],
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
    [files: ~w(src doc rebar.config README.markdown LICENSE),
     maintainers: ["Michael Truog"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/okeuday/quickrand"}]
   end
end
