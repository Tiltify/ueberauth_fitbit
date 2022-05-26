defmodule Ueberauth.Strategy.FitbitTest do
  use ExUnit.Case, async: true
  use Plug.Test

  import Mock
  # alias Plug.Conn
  # alias Ueberauth.Strategy.Fitbit
  # import Ueberauth.Strategy.Helpers

  alias Plug.Conn.Query

  setup do
    Application.put_env(:ueberauth, Ueberauth.Strategy.Fitbit.OAuth,
      client_id: "client_id",
      client_secret: "client_secret",
      redirect_uri: "https://myapp.com/auth/fitbit/callback",
      scope: "activity nutrition profile settings sleep social weight"
    )
  end

  describe "handle_request!" do
    test "redirects to fitbit authorization url" do
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
               "scope" => "activity nutrition profile settings sleep social weight"
               #  "code_challenge" => _,
               #  "code_challenge_method" => "S256"
             } = Query.decode(redirect_uri.query)
    end

    test "adds state param to cookies" do
      conn = conn(:get, "/auth/fitbit", %{})
      routes = Ueberauth.init()
      resp = Ueberauth.call(conn, routes)
      assert %{same_site: "Lax", value: state_value} = resp.resp_cookies["ueberauth.state_param"]

      assert is_binary(state_value)
    end

    # test "redirects to fitbit authorization url using pkce" do
    #   conn = conn(:get, "/auth/fitbit", %{})
    #   routes = Ueberauth.init()
    #   resp = Ueberauth.call(conn, routes)

    #   assert resp.status == 302
    #   assert [location] = get_resp_header(resp, "location")
    #   redirect_uri = URI.parse(location)

    #   assert redirect_uri.host == "www.fitbit.com"
    #   assert redirect_uri.path == "/oauth2/authorize"

    #   assert %{
    #            "client_id" => "client_id",
    #            "redirect_uri" => "http://www.example.com/auth/fitbit/callback",
    #            "response_type" => "code",
    #            "scope" =>
    #              "activity nutrition profile settings sleep social weight"
    #             "code_challenge" => _,
    #             "code_challenge_method" => "S256"
    #          } = Query.decode(redirect_uri.query)
    # end
  end

  describe "handle_callback!" do
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

    test "ignores csrf when configured and receives token" do
      Application.put_env(:ueberauth, Ueberauth.Strategy.Fitbit.OAuth,
        client_id: "client_id",
        client_secret: "client_secret",
        redirect_uri: "https://myapp.com/auth/fitbit/callback",
        ignores_csrf_attack: true
      )

      with_mocks([
        {OAuth2.Client, [:passthrough],
         [get_token: &get_token_mock/2, get: &get_user_profile_mock/4]}
      ]) do
        conn = conn(:get, "/auth/fitbit/callback", %{code: "fitbit_success_code"})
        routes = Ueberauth.init([])

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

    defp get_token_mock(%OAuth2.Client{} = client, code: "fitbit_success_code") do
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

    # defp get_token_mock(%OAuth2.Client{} = _client, code: "<invalid_code>") do
    #   {:error,
    #    %OAuth2.Response{
    #      body: %{
    #        "errors" => [
    #          %{
    #            "errorType" => "invalid_grant",
    #            "message" =>
    #              "Authorization code invalid: <invalid_code> Visit https://dev.fitbit.com/docs/oauth2 for more information on the Fitbit Web API authorization process."
    #          }
    #        ],
    #        "success" => false
    #      },
    #      status_code: 400
    #    }}
    # end

    # test "requests token with callback code code" do
    #   conn = conn(:get, "/auth/fitbit/callback", %{code: "fitbit_success_code"})
    #   # state: csrf_state, scope: "read"
    #   # |> set_csrf_cookies(csrf_conn)

    #   routes = Ueberauth.init([])
    #   assert %Plug.Conn{assigns: %{ueberauth_auth: auth}} = Ueberauth.call(conn, routes)

    #   # utc_now =
    #   #   DateTime.utc_now()
    #   #   |> DateTime.truncate(:second)
    #   #   |> DateTime.to_unix()

    #   # token_expires_at = utc_now + @token_ttl

    #   # assert conn == %{plug_session: %{}, plug_session_fetch: :done}
    # end
  end

  # defp set_options(routes, conn, opt) do
  #   case Enum.find_index(routes, &(elem(&1, 0) == {conn.request_path, conn.method})) do
  #     nil ->
  #       routes

  #     idx ->
  #       update_in(routes, [Access.at(idx), Access.elem(1), Access.elem(2)], &%{&1 | options: opt})
  #   end
  # end

  # setup_with_mocks([
  #   {OAuth2.Client, [:passthrough],
  #    [
  #      get_token: &oauth2_get_token/2,
  #      get: &oauth2_get/4
  #    ]}
  # ]) do
  #   Application.put_env(:ueberauth, Ueberauth.Strategy.Fitbit.OAuth,
  #     client_id: "238CV8",
  #     client_secret: "47e5983a2ed09694f2aa3b7b2df65adb",
  #     redirect_uri: "http://myapp.com/auth/callback"
  #   )

  #   # Create a connection with Ueberauth's CSRF cookies so they can be recycled during tests
  #   # routes = Ueberauth.init([])
  #   # csrf_conn = conn(:get, "/auth/fitbit", %{}) |> Ueberauth.call(routes)
  #   # csrf_state = with_state_param([], csrf_conn) |> Keyword.get(:state)

  #   # {:ok, csrf_conn: csrf_conn, csrf_state: csrf_state}
  #   :ok
  # end

  # @token_ttl 6 * 60 * 60

  # describe "handle_request!" do
  #   test "redirects to authorization url" do
  #     conn = conn(:get, "/auth/fitbit", %{})

  #     routes =
  #       Ueberauth.init()
  #       |> set_options(conn,
  #         default_scope:
  #           "weight location settings profile nutrition activity sleep heartrate social"
  #       )

  #     resp = Ueberauth.call(conn, routes)

  #     assert resp.status == 302
  #     assert [location] = get_resp_header(resp, "location")
  #     redirect_uri = URI.parse(location)

  #     assert redirect_uri.host == "www.fitbit.com"
  #     assert redirect_uri.path == "/oauth2/authorize"

  #     assert %{
  #              "client_id" => "client_id",
  #              "redirect_uri" => "http://www.example.com/auth/fitbit/callback",
  #              "response_type" => "code",
  #              "scope" =>
  #                "weight location settings profile nutrition activity sleep heartrate social",
  #              "code_challenge" => _,
  #              "code_challenge_method" => "S256"
  #            } = Query.decode(redirect_uri.query)
  #   end
  # end

  # test "handle_callback! assigns required fields on successful auth" do
  # # ,
  # # %{
  # #   csrf_state: csrf_state,
  # #   csrf_conn: csrf_conn
  # # } do
  #   conn =
  #     conn(:get, "/auth/fitbit/callback", %{
  #       code: "success_code",
  #       # state: csrf_state,
  #       scope: "read"
  #     })
  #     # |> set_csrf_cookies(csrf_conn)

  #   routes = Ueberauth.init([])
  #   assert %Plug.Conn{assigns: %{ueberauth_auth: auth}} = Ueberauth.call(conn, routes)

  #   utc_now =
  #     DateTime.utc_now()
  #     |> DateTime.truncate(:second)
  #     |> DateTime.to_unix()

  #   token_expires_at = utc_now + @token_ttl

  #   assert conn == %{plug_session: %{}, plug_session_fetch: :done}
  #   assert auth.credentials.token == "success_token"
  #   assert auth.credentials.refresh_token == "refresh_token"

  #   assert auth.credentials.expires_at == token_expires_at
  #   assert auth.info.first_name == "Fred"

  #   assert auth.info.last_name == "Jones"
  #   assert auth.info.name == "Fred Jones"
  #   assert auth.info.nickname == "Frejones"
  #   assert auth.uid == "123123123"
  # end

  # def set_options(routes, conn, opt) do
  #   case Enum.find_index(routes, &(elem(&1, 0) == {conn.request_path, conn.method})) do
  #     nil ->
  #       routes

  #     idx ->
  #       update_in(routes, [Access.at(idx), Access.elem(1), Access.elem(2)], &%{&1 | options: opt})
  #   end
  # end

  # defp response(body, code \\ 200), do: {:ok, %OAuth2.Response{status_code: code, body: body}}

  # defp oauth2_get_token(%{client_secret: "client_secret"} = client, code: "success_code") do
  #   token =
  #     OAuth2.AccessToken.new(%{
  #       "access_token" => "success_token",
  #       "refresh_token" => "refresh_token",
  #       "expires_in" => @token_ttl
  #     })

  #   {:ok, %{client | token: token}}
  # end

  # defp oauth2_get(%{token: token, params: params}, "/1/user/-/profile.json", _, _) do
  #   assert %{access_token: "success_token", refresh_token: "refresh_token"} = token
  #   assert %{"client_secret" => "client_secret"} = params

  #   response(%{
  #     "user" => %{
  #       "encodedId" => "123123123",
  #       "avatar" => nil,
  #       "aboutMe" => "some description",
  #       "fullName" => "Fred Jones",
  #       "firstName" => "Fred",
  #       "lastName" => "Jones",
  #       "displayName" => "Frejones",
  #       "gender" => "Male",
  #       "city" => "New York",
  #       "state" => "NY"
  #     }
  #   })
  # end

  # defp set_csrf_cookies(conn, csrf_conn) do
  #   conn
  #   |> init_test_session(%{})
  #   |> recycle_cookies(csrf_conn)
  #   |> fetch_cookies()
  # end
end
