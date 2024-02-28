package httpapi.authz

#HTTP API request

import input

default allow = false 

allow {
    input.path == "home"
    input.user == "james"
}