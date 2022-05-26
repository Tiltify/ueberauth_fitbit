defmodule Ueberauth.Strategy.Fitbit.OAuth do
  @moduledoc """
  OAuth2 for Fitbit.

  Add `client_id` and `client_secret` to your configuration:

  config :ueberauth, Ueberauth.Strategy.Fitbit.OAuth,
    client_id: System.get_env("FITBIT_CLIENT_ID"),
    client_secret: System.get_env("FITBIT_CLIENT_SECRET"),
  """
  use OAuth2.Strategy
  alias OAuth2.Strategy.AuthCode

  @fitbit_config [
    strategy: __MODULE__,
    headers: [{"Content-Type", "application/x-www-form-urlencoded"}],
    site: "https://api.fitbit.com/",
    authorize_url: "https://www.fitbit.com/oauth2/authorize",
    token_url: "https://api.fitbit.com/oauth2/token"
  ]

  defp client(opts \\ []) do
    opts =
      @fitbit_config ++
        oauth_config() ++
        opts

    opts
    |> OAuth2.Client.new()
    |> OAuth2.Client.put_serializer("application/json", Jason)
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth. No need to call this usually.
  client_id:client_secret
  """
  def authorize_url!(opts \\ []) do
    OAuth2.Client.authorize_url!(client(), opts)
  end

  def get_token(params \\ [], opts \\ []) do
    client =
      opts
      |> client()
      |> put_header("Authorization", basic_token())

    params = Enum.reject(params, fn {_key, value} -> is_nil(value) end)

    OAuth2.Client.get_token(client, params)
  end

  def get(token, url, headers \\ [], opts \\ []) do
    OAuth2.Client.get(client(token: token), url, headers, opts)
  end

  defp basic_token() do
    config = oauth_config()
    token = Base.encode64("#{config[:client_id]}:#{config[:client_secret]}")

    "Basic #{token}"
  end

  defp oauth_config(), do: Application.get_env(:ueberauth, Ueberauth.Strategy.Fitbit.OAuth)

  # Strategy Callbacks

  def authorize_url(client, params) do
    AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_header("Authorization", basic_token())
    |> put_header("Accept", "application/json")
    |> AuthCode.get_token(params, headers)
  end
end
