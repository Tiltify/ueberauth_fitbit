defmodule Ueberauth.Strategy.Fitbit do
  @moduledoc """
  Fitbit Strategy for Üeberauth.
  """

  use Ueberauth.Strategy,
    strategy: __MODULE__,
    headers: [{"Content-Type", "application/x-www-form-urlencoded"}],
    site: "https://api.fitbit.com/",
    authorize_url: "https://www.fitbit.com/oauth2/authorize",
    token_url: "https://api.fitbit.com/oauth2/token",
    default_scope: "profile",
    uid_field: :user_id,
    oauth2_module: Ueberauth.Strategy.Fitbit.OAuth,
    ignores_csrf_attack: false

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Strategy.Fitbit.OAuth

  @doc """
  Handles initial request for Fitbit authentication.
  """
  def handle_request!(conn) do
    scope =
      strategy_config()[:default_scope] ||
        Keyword.get(default_options(), :default_scope)

    state = Map.get(conn.params, "state", conn.private[:ueberauth_state_param])
    opts = [redirect_uri: callback_url(conn), scope: scope, state: state]
    url = OAuth.authorize_url!(opts)

    redirect!(conn, url)
  end

  @doc """
  Handles the callback from Fitbit.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    body_params = [code: code, redirect_uri: callback_url(conn)]

    case OAuth.get_token(body_params) do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %OAuth2.Client{token: token}} ->
        fetch_user(conn, token)

      {:error, %OAuth2.Response{status_code: status_code}} ->
        set_errors!(conn, [error("OAuth2", status_code)])

      {:error, %OAuth2.Response{body: %{"errors" => errors, "success" => false}}} ->
        set_errors!(conn, [error("OAuth2", errors)])

      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:fitbit_user, nil)
    |> put_private(:fitbit_token, nil)
  end

  @doc """
  Fetches the uid field from the response.
  """
  def uid(conn) do
    # encodedId is the only reasonable uid field for this strategy
    Map.get(conn.private.fitbit_user, "encodedId")
  end

  @doc """
  Includes the credentials from the fitbit response.
  """
  def credentials(conn) do
    token = conn.private.fitbit_token
    scopes = (token.other_params["scope"] || "") |> String.split(" ")

    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      scopes: scopes,
      token: token.access_token,
      refresh_token: token.refresh_token,
      other: %{token_type: token.token_type}
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.fitbit_user

    %Info{
      first_name: user["firstName"],
      last_name: user["lastName"],
      name: user["fullName"] || user["displayName"],
      nickname: user["displayName"],
      description: user["aboutMe"],
      image: user["avatar"],
      urls: %{
        avatar: user["avatar"],
        avatar150: user["avatar150"]
      }
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the fitbit callback.
  """
  def extra(conn) do
    user = conn.private.fitbit_user

    %Extra{
      raw_info: %{
        token: conn.private.fitbit_token,
        user: conn.private.fitbit_user,
        gender: user["gender"],
        city: user["city"],
        state: user["state"]
      }
    }
  end

  defp strategy_config(), do: Application.get_env(:ueberauth, Ueberauth.Strategy.Fitbit)

  defp fetch_user(conn, token) do
    conn = put_private(conn, :fitbit_token, token)
    profile_path = "1/user/-/profile.json"

    case OAuth.get(token, profile_path) do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %OAuth2.Response{status_code: status_code, body: res}} when status_code in 200..399 ->
        put_private(conn, :fitbit_user, res["user"])

      {:error, %OAuth2.Response{status_code: status_code}} ->
        set_errors!(conn, [error("OAuth2", status_code)])

      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end
end
