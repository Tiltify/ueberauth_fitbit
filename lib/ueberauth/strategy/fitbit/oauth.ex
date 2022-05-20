defmodule Ueberauth.Strategy.Fitbit.OAuth do
  @moduledoc """
  OAuth2 for Fitbit.

  Add `client_id` and `client_secret` to your configuration:

  config :ueberauth, Ueberauth.Strategy.Fitbit.OAuth,
    client_id: System.get_env("FITBIT_APP_ID"),
    client_secret: System.get_env("FITBIT_APP_SECRET")
  """
  use OAuth2.Strategy
  alias OAuth2.Strategy.AuthCode

  @defaults [
    strategy: __MODULE__,
    site: "https://api.fitbit.com/",
    authorize_url: "https://www.fitbit.com/oauth2/authorize",
    token_url: "https://api.fitbit.com/oauth2/token",
    headers: [{"Content-Type", "application/x-www-form-urlencoded"}]
  ]

  @doc false
  def options(opts \\ []) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Fitbit.OAuth)

    @defaults
    |> Keyword.merge(config)
    |> Keyword.merge(opts)
  end

  @doc """
  Generate Authentication: Basic Base64<CLIENT_ID>:<CLIENT_SECRET>
  """
  def auth_sig(opts \\ []) do
    opts = options(opts)
    sig = Base.encode64(opts[:client_id] <> ":" <> opts[:client_secret])

    "Basic #{sig}"
  end

  @doc """
  Construct a client for requests to Fitbit.

  This will be setup automatically for you in `Ueberauth.Strategy.Fitbit`.
  These options are only useful for usage outside the normal callback phase of Ueberauth.
  """
  def client(opts \\ []) do
    json_library = Ueberauth.json_library()

    opts
    |> options()
    |> OAuth2.Client.new()
    |> OAuth2.Client.put_serializer("application/json", json_library)
  end

  @doc """
  Construct a signed client for token and refresh token requests
  """
  def signed_client(opts \\ []) do
    opts
    |> client
    |> put_header("Authorization", auth_sig(opts))
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth. No need to call this usually.
  client_id:client_secret
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client()
    |> OAuth2.Client.authorize_url!(params)
  end

  def get(token, url, headers \\ [], opts \\ []) do
    client(token: token)
    |> put_param(:client_secret, client().client_secret)
    |> OAuth2.Client.get(url, headers, opts)
  end

  def get_token(params \\ [], opts \\ []) do
    client = opts |> signed_client()
    code = Map.get(params, "code")

    case OAuth2.Client.get_token(client, code: code) do
      {:error, %{body: %{"errors" => errors, "message" => description}}} ->
        {:error, {errors, description}}

      {:ok, %{token: %{access_token: nil} = token}} ->
        %{"errors" => errors, "message" => description} = token.other_params
        {:error, {errors, description}}

      {:ok, %{token: token}} ->
        {:ok, token}
    end
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_param(:client_secret, client.client_secret)
    |> put_header("Accept", "application/json")
    |> AuthCode.get_token(params, headers)
  end
end
