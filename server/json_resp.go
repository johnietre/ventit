package server

import (
  "net/http"

  userpkg "github.com/johnietre/ventit/user"
)

type JsonResp map[string]any

func newResp(status int) JsonResp {
  return JsonResp{"status": status}
}

func newOkResp() JsonResp {
  return JsonResp{"status": http.StatusOK}
}

func newErrResp(status int, msg string) JsonResp {
  return JsonResp{"status": status, "error": msg}
}

func newTokResp(user userpkg.User, tok string) JsonResp {
  return JsonResp{"status": http.StatusOK, "user": user, "token": tok}
}

func (resp JsonResp) withStatus(status int) JsonResp {
  resp["status"] = status
  return resp
}

func (resp JsonResp) withToken(tok string) JsonResp {
  resp["token"] = tok
  return resp
}

func (resp JsonResp) withUser(user userpkg.User) JsonResp {
  resp["user"] = user
  return resp
}

func (resp JsonResp) withData(data any) JsonResp {
  resp["data"] = data
  return resp
}

func (resp JsonResp) withError(errMsg string) JsonResp {
  resp["error"] = errMsg
  return resp
}

func (resp JsonResp) withKeyVal(key string, val any) JsonResp {
  resp[key] = val
  return resp
}
