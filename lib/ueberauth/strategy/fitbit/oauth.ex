defmodule Ueberauth.Strategy.Fitbit.OAuth do
  @moduledoc """
  OAuth2 for Fitbit.

  Add `client_id` and `client_secret` to your configuration:

  config :ueberauth, Ueberauth.Strategy.Fitbit.OAuth,
    client_id: System.get_env("FITBIT_CLIENT_ID"),
    client_secret: System.get_env("FITBIT_CLIENT_SECRET"),
    scope: "profile weight location settings profile nutrition activity sleep heartrate social"
  """
  use OAuth2.Strategy
  alias OAuth2.Strategy.AuthCode

  @default_scope "profile"

  @fitbit_config [
    strategy: __MODULE__,
    headers: [{"Content-Type", "application/x-www-form-urlencoded"}],
    site: "https://api.fitbit.com/",
    authorize_url: "https://www.fitbit.com/oauth2/authorize",
    token_url: "https://api.fitbit.com/oauth2/token",
    scope: @default_scope
  ]

  @doc """
  Construct a client for requests to Fitbit.

  This will be setup automatically for you in `Ueberauth.Strategy.Fitbit`.
  These options are only useful for usage outside the normal callback phase of Ueberauth.
  """
  def client(opts \\ []) do
    opts =
      @fitbit_config ++
        app_config() ++
        opts

    opts
    |> OAuth2.Client.new()
    |> OAuth2.Client.put_serializer("application/json", Jason)
  end

  @doc """
  Generate Authentication: Basic Base64<CLIENT_ID>:<CLIENT_SECRET>
  """
  def basic_token() do
    config = app_config()
    sig = Base.encode64(config[:client_id] <> ":" <> config[:client_secret])

    "Basic #{sig}"
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth. No need to call this usually.
  client_id:client_secret
  """
  def authorize_url!(opts \\ []) do
    opts = if is_nil(opts[:scope]), do: opts ++ [scope: @default_scope], else: opts
    OAuth2.Client.authorize_url!(client(), opts)
  end

  def get_token(params \\ [], opts \\ []) do
    client =
      opts
      |> client()
      |> put_header("Authorization", basic_token())

    OAuth2.Client.get_token(client, code: params[:code])
  end

  def get(token, url, headers \\ [], opts \\ []) do
    OAuth2.Client.get(client(token: token), url, headers, opts)

    # case OAuth2.Client.get(client(token: token), url, headers, opts) do
    #   {:error, %OAuth2.Error{reason: error_reason}} ->
    #     {:error, {error_reason}}

    #   {:error, %OAuth2.Response{status_code: body: %{"success" => false, "errors" => errors}}} ->
    #     {:error, {errors}}

    #   {:ok, %OAuth2.Response{body: user}} ->
    #     {:ok, user}
    # end
  end

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

  defp app_config(), do: Application.get_env(:ueberauth, Ueberauth.Strategy.Fitbit.OAuth)
end
