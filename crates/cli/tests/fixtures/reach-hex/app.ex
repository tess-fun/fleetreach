defmodule MyApp.Endpoint do
  alias Plug.Conn
  def call(conn), do: Plug.Conn.send_resp(conn, 200, "ok")
end
