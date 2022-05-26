import Config
config :oauth2, debug: true

config :ueberauth, Ueberauth,
  providers: [
    fitbit: {Ueberauth.Strategy.Fitbit, []}
  ]
