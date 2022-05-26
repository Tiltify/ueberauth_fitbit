defmodule Ueberauth.Strategy.Fitbit.OAuthTest do
  use ExUnit.Case, async: true
  use Plug.Test

  import Mock
  alias Ueberauth.Strategy.Fitbit.OAuth

  setup do
    Application.put_env(:ueberauth, Ueberauth.Strategy.Fitbit.OAuth,
      client_id: "client_id",
      client_secret: "client_secret",
      redirect_uri: "https://myapp.com/auth/fitbit/callback"
    )
  end

  describe "client/0" do
    test "returns client" do
      client = OAuth.client()

      assert client == client()
    end
  end

  describe "basic_token/0" do
    setup do
      Application.put_env(:ueberauth, Ueberauth.Strategy.Fitbit.OAuth,
        client_id: "client_id",
        client_secret: "client_secret",
        redirect_uri: "https://myapp.com/auth/fitbit/callback"
      )
    end

    test "returns basic token" do
      assert OAuth.basic_token() == "Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ="
    end
  end

  describe "authorize_url!/2" do
    @default_expected_url "https://www.fitbit.com/oauth2/authorize?client_id=client_id&redirect_uri=https%3A%2F%2Fmyapp.com%2Fauth%2Ffitbit%2Fcallback&response_type=code"

    test "returns authorization url" do
      assert OAuth.authorize_url!() == "#{@default_expected_url}&scope=profile"
    end

    test "returns authorization url with selected scope" do
      assert OAuth.authorize_url!(scope: "profile activity") ==
               "#{@default_expected_url}&scope=profile+activity"
    end
  end

  describe "get_token/" do
    test "errors when not granted" do
      with_mocks([{OAuth2.Client, [:passthrough], [get_token: &get_token_mock/2]}]) do
        params = [code: "<invalid_code>"]
        assert {:error, response} = OAuth.get_token(params, [])

        assert response ==
                 %OAuth2.Response{
                   body: %{
                     "errors" => [
                       %{
                         "errorType" => "invalid_grant",
                         "message" =>
                           "Authorization code invalid: <invalid_code> Visit https://dev.fitbit.com/docs/oauth2 for more information on the Fitbit Web API authorization process."
                       }
                     ],
                     "success" => false
                   },
                   headers: [],
                   status_code: 400
                 }
      end
    end

    test "get access and refresh tokens" do
      with_mocks([{OAuth2.Client, [:passthrough], [get_token: &get_token_mock/2]}]) do
        params = [code: "some_special_code"]
        assert {:ok, client} = OAuth.get_token(params, [])

        assert client.token == %OAuth2.AccessToken{
                 access_token: "<access_token>",
                 refresh_token: "<refresh_token>",
                 token_type: "Bearer",
                 expires_at: 1_653_605_403,
                 other_params: %{
                   "scope" => "profile activity nutrition settings",
                   "user_id" => "123ABC"
                 }
               }
      end
    end
  end

  describe "get/4" do
    test "get user info" do
      with_mocks([{OAuth2.Client, [:passthrough], [get: &get_user_profile_mock/4]}]) do
        token = "<access_token>"
        url = "1/user/-/profile.json"
        headers = []
        opts = []

        assert OAuth.get(token, url, headers, opts) ==
                 {:ok,
                  %OAuth2.Response{
                    body: %{
                      "age" => 26,
                      "avatar" =>
                        "https://static0.fitbit.com/images/profile/defaultProfile_100.png",
                      "avatar150" =>
                        "https://static0.fitbit.com/images/profile/defaultProfile_150.png",
                      "avatar640" =>
                        "https://static0.fitbit.com/images/profile/defaultProfile_640.png",
                      "dateOfBirth" => "1995-08-08",
                      "displayName" => "John D.",
                      "distanceUnit" => "METRIC",
                      "encodedId" => "ABC123",
                      "firstName" => "John",
                      "foodsLocale" => "en_US",
                      "fullName" => "John Doe",
                      "gender" => "MALE",
                      "glucoseUnit" => "en_US",
                      "height" => 170.0,
                      "heightUnit" => "METRIC",
                      "languageLocale" => "en_US",
                      "lastName" => "Doe",
                      "locale" => "en_US",
                      "offsetFromUTCMillis" => -10_800_000,
                      "swimUnit" => "METRIC",
                      "timezone" => "America/Sao_Paulo",
                      "waterUnit" => "en_US",
                      "waterUnitName" => "fl oz",
                      "weight" => 0.0,
                      "weightUnit" => "METRIC"
                    },
                    headers: [],
                    status_code: nil
                  }}
      end
    end

    test "returns error when user is not found" do
      with_mocks([{OAuth2.Client, [:passthrough], [get: &get_user_profile_mock/4]}]) do
        token = "<access_token>"
        url = "1/user/invalid-user-id/profile.json"
        headers = []
        opts = []

        assert OAuth.get(token, url, headers, opts) ==
                 {:ok, %OAuth2.Response{body: "", headers: [], status_code: 301}}
      end
    end
  end

  defp get_token_mock(%OAuth2.Client{} = client, code: "some_special_code") do
    token = %OAuth2.AccessToken{
      access_token: "<access_token>",
      expires_at: 1_653_605_403,
      other_params: %{
        "scope" => "profile activity nutrition settings",
        "user_id" => "123ABC"
      },
      refresh_token: "<refresh_token>",
      token_type: "Bearer"
    }

    {:ok, Map.put(client, :token, token)}
  end

  defp get_token_mock(%OAuth2.Client{} = _client, code: "<invalid_code>") do
    {:error,
     %OAuth2.Response{
       body: %{
         "errors" => [
           %{
             "errorType" => "invalid_grant",
             "message" =>
               "Authorization code invalid: <invalid_code> Visit https://dev.fitbit.com/docs/oauth2 for more information on the Fitbit Web API authorization process."
           }
         ],
         "success" => false
       },
       status_code: 400
     }}
  end

  defp get_user_profile_mock(
         %OAuth2.Client{token: %OAuth2.AccessToken{access_token: "<access_token>"}},
         "1/user/-/profile.json",
         _headers,
         _opts
       ) do
    user_profile_response = %{
      "encodedId" => "ABC123",
      "timezone" => "America/Sao_Paulo",
      "dateOfBirth" => "1995-08-08",
      "age" => 26,
      "gender" => "MALE",
      "firstName" => "John",
      "lastName" => "Doe",
      "fullName" => "John Doe",
      "displayName" => "John D.",
      "weight" => 0.0,
      "height" => 170.0,
      "offsetFromUTCMillis" => -10_800_000,
      "avatar" => "https://static0.fitbit.com/images/profile/defaultProfile_100.png",
      "avatar640" => "https://static0.fitbit.com/images/profile/defaultProfile_640.png",
      "avatar150" => "https://static0.fitbit.com/images/profile/defaultProfile_150.png",
      "waterUnitName" => "fl oz",
      "swimUnit" => "METRIC",
      "distanceUnit" => "METRIC",
      "weightUnit" => "METRIC",
      "heightUnit" => "METRIC",
      "waterUnit" => "en_US",
      "foodsLocale" => "en_US",
      "languageLocale" => "en_US",
      "locale" => "en_US",
      "glucoseUnit" => "en_US"
    }

    {:ok, %OAuth2.Response{body: user_profile_response}}
  end

  defp get_user_profile_mock(
         %OAuth2.Client{token: %OAuth2.AccessToken{access_token: "<access_token>"}},
         "1/user/invalid-user-id/profile.json",
         _headers,
         _opts
       ) do
    {:ok, %OAuth2.Response{body: "", headers: [], status_code: 301}}
  end

  defp client(token \\ nil) do
    %OAuth2.Client{
      authorize_url: "https://www.fitbit.com/oauth2/authorize",
      client_id: "client_id",
      client_secret: "client_secret",
      headers: [{"Content-Type", "application/x-www-form-urlencoded"}],
      params: %{},
      redirect_uri: "https://myapp.com/auth/fitbit/callback",
      ref: nil,
      request_opts: [],
      serializers: %{"application/json" => Jason},
      site: "https://api.fitbit.com/",
      strategy: Ueberauth.Strategy.Fitbit.OAuth,
      token: token,
      token_method: :post,
      token_url: "https://api.fitbit.com/oauth2/token"
    }
  end
end
