import Config
config :oauth2, debug: true

config :ueberauth, Ueberauth,
  providers: [
    fitbit: {Ueberauth.Strategy.Fitbit, []}
  ]

config :ueberauth, Ueberauth.Strategy.Fitbit.OAuth,
  client_id: "client_id",
  client_secret: "client_secret",
  token_url: "token_url"
