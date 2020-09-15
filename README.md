# kind-no-snat-interface plugin

## Overview

This plugin creates firewall rules to bypass kindnet snat to allow for container interfaces.
It does not create any network interfaces and therefore does not set up connectivity by itself.
It is intended to be used as a chained plugins.

## Operation
The following network configuration file

```json
{
    "cniVersion": "0.3.1",
    "name": "bridge-firewalld",
    "plugins": [
      {
        "type": "bridge",
        "bridge": "cni0",
      },
      {
        "type": "kind-no-snat-interface"
      }
    ]
}
```

will allow any interfaces configured by bypass kindnet masquerading.

A successful result would simply be an empty result, unless a previous plugin passed a previous result, in which case this plugin will return that previous result.

The above example will create two new iptables chains in the `filter` table and add rules that allow the given interface to send/receive traffic.
