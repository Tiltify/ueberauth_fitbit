defmodule Ueberauth.Strategy.FitbitTest do
  use ExUnit.Case, async: false
  use Plug.Test

  import Mock
  alias Ueberauth.Strategy.Helpers

  alias Plug.Conn.Query

  setup do
    Application.put_env(:ueberauth, Ueberauth,
      providers: [fitbit: {Ueberauth.Strategy.Fitbit, []}]
    )

    Application.put_env(:ueberauth, Ueberauth.Strategy.Fitbit.OAuth,
      client_id: "client_id",
      client_secret: "client_secret"
    )

    :ok
  end

  describe "handle_request!" do
    test "redirects to fitbit authorization url" do
      Application.put_env(:ueberauth, Ueberauth.Strategy.Fitbit,
        default_scope: "activity nutrition profile settings sleep social weight"
      )

      conn = conn(:get, "/auth/fitbit", %{})
      routes = Ueberauth.init()
      resp = Ueberauth.call(conn, routes)

      assert resp.status == 302
      assert [location] = get_resp_header(resp, "location")
      redirect_uri = URI.parse(location)

      assert redirect_uri.host == "www.fitbit.com"
      assert redirect_uri.path == "/oauth2/authorize"

      assert %{
               "client_id" => "client_id",
               "redirect_uri" => "http://www.example.com/auth/fitbit/callback",
               "response_type" => "code",
               "scope" => "activity nutrition profile settings sleep social weight",
               "state" => state
             } = Query.decode(redirect_uri.query)

      assert String.length(state) == 24
    end

    test "adds state param to cookies" do
      conn = conn(:get, "/auth/fitbit", %{})
      routes = Ueberauth.init()
      conn = Ueberauth.call(conn, routes)
      assert %{same_site: "Lax", value: state_value} = conn.resp_cookies["ueberauth.state_param"]

      assert is_binary(state_value)
    end
  end

  describe "handle_callback!" do
    test "receives token" do
      with_mocks([
        {OAuth2.Client, [:passthrough],
         [
           get_token: fn %OAuth2.Client{} = client,
                         code: "fitbit_success_code",
                         redirect_uri: "http://www.example.com/auth/fitbit/callback" ->
             assert client.headers == [
                      {"Content-Type", "application/x-www-form-urlencoded"},
                      {"authorization", "Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ="}
                    ]

             assert client.serializers == %{"application/json" => Jason}
             assert client.site == "https://api.fitbit.com/"

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
           end,
           get: &get_user_profile_mock/4
         ]}
      ]) do
        routes = Ueberauth.init([])
        csrf_conn = conn(:get, "/auth/fitbit", %{}) |> Ueberauth.call(routes)

        state =
          Helpers.with_state_param([], csrf_conn)
          |> Keyword.get(:state)

        conn =
          :get
          |> conn("/auth/fitbit/callback", %{code: "fitbit_success_code", state: state})
          |> set_csrf_cookies(csrf_conn)

        assert %Plug.Conn{assigns: assigns} = Ueberauth.call(conn, routes)

        assert assigns == %{
                 ueberauth_auth: %Ueberauth.Auth{
                   credentials: %Ueberauth.Auth.Credentials{
                     expires: true,
                     expires_at: 1_653_605_403,
                     other: %{token_type: "Bearer"},
                     refresh_token: "<refresh_token>",
                     scopes: ["profile", "activity", "nutrition", "settings"],
                     secret: nil,
                     token: "<access_token>",
                     token_type: nil
                   },
                   extra: %Ueberauth.Auth.Extra{
                     raw_info: %{
                       city: nil,
                       gender: "MALE",
                       state: nil,
                       token: %OAuth2.AccessToken{
                         access_token: "<access_token>",
                         expires_at: 1_653_605_403,
                         other_params: %{
                           "scope" => "profile activity nutrition settings",
                           "user_id" => "123ABC"
                         },
                         refresh_token: "<refresh_token>",
                         token_type: "Bearer"
                       },
                       user: %{
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
                       }
                     }
                   },
                   info: %Ueberauth.Auth.Info{
                     birthday: nil,
                     description: nil,
                     email: nil,
                     first_name: "John",
                     image: "https://static0.fitbit.com/images/profile/defaultProfile_100.png",
                     last_name: "Doe",
                     location: nil,
                     name: "John Doe",
                     nickname: "John D.",
                     phone: nil,
                     urls: %{
                       avatar: "https://static0.fitbit.com/images/profile/defaultProfile_100.png",
                       avatar150:
                         "https://static0.fitbit.com/images/profile/defaultProfile_150.png"
                     }
                   },
                   provider: :fitbit,
                   strategy: Ueberauth.Strategy.Fitbit,
                   uid: "ABC123"
                 }
               }
      end
    end

    test "fails without valid csrf state" do
      conn = conn(:get, "/auth/fitbit/callback", %{code: "fitbit_success_code"})
      routes = Ueberauth.init([])
      assert %Plug.Conn{assigns: assigns} = Ueberauth.call(conn, routes)

      assert %{
               ueberauth_failure: %Ueberauth.Failure{
                 errors: [csrf_error],
                 provider: :fitbit,
                 strategy: Ueberauth.Strategy.Fitbit
               }
             } = assigns

      assert csrf_error == %Ueberauth.Failure.Error{
               message: "Cross-Site Request Forgery attack",
               message_key: :csrf_attack
             }
    end
  end

  defp get_user_profile_mock(
         %OAuth2.Client{token: %OAuth2.AccessToken{access_token: "<access_token>"}},
         "1/user/-/profile.json",
         _headers,
         _opts
       ) do
    user_profile = %{
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

    {:ok,
     %OAuth2.Response{
       status_code: 200,
       body: %{"user" => user_profile},
       headers: [
         {"connection", "keep-alive"},
         {"fitbit-rate-limit-limit", "150"},
         {"fitbit-rate-limit-remaining", "150"},
         {"fitbit-rate-limit-reset", "3029"}
       ]
     }}
  end

  defp set_csrf_cookies(conn, csrf_conn) do
    conn
    |> init_test_session(%{})
    |> recycle_cookies(csrf_conn)
    |> fetch_cookies()
  end
end
