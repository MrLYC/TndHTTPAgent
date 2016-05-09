#!/bin/bash

setup() {
  ./http_agent.py --port="${HttpAgentServerPort}" --debug >/dev/null 2>&1 &
  export HttpAgentServerPid=$!

  trap "teardown" INT
  
  until curl "http://localhost:${HttpAgentServerPort}" > /dev/null 2>&1; do
    sleep 1
  done

  echo "ready"
}

teardown() {
  kill -9 ${HttpAgentServerPid}
  wait

  echo "done"
  exit
}

export TestScriptDirectory=$(dirname "$0")
export HttpAgentServerPort=8089

setup

python ${TestScriptDirectory}/http_agent_feature_test.py -v

teardown
