:global scriptname "DoH block"
:global ipv4file "block_doh_dns/doh_ipv4.txt"
:global ipv4url "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/doh.txt"
:global ipv4list "DoH Servers"

:log info "[$scriptname] Downloading IP list"
:global result [/tool fetch url=$ipv4url mode=https dst-path=$ipv4file as-value]
:if ($result->"status" = "finished") do={
    :log info "[$scriptname] Downloaded IP list"

    :if ([/file get $ipv4file size] < 65536) do={
        :log info "[$scriptname] IP list file is smaller than 64KiB - Loading file now."
        :global ipv4content [/file get $ipv4file contents]

        # Replace newlines (\n) with commas
        :log info "[$scriptname] Started replacing newlines."
        :global find "\n"
        :global replace ","
        :while condition=[find $ipv4content $find] do={
            :set ipv4content ("$[pick $ipv4content 0 ([find $ipv4content $find]) ]".$replace."$[pick $ipv4content ([find $ipv4content $find]+1) ([len $ipv4content])]")
        }
        :log info "[$scriptname] Finished replacing newlines."

        # Replace carriage returns (\r) with nothing
        :log info "[$scriptname] Started replacing carriage returns."
        :global find "\r"
        :global replace ""
        :while condition=[find $ipv4content $find] do={
            :set ipv4content ("$[pick $ipv4content 0 ([find $ipv4content $find]) ]".$replace."$[pick $ipv4content ([find $ipv4content $find]+1) ([len $ipv4content])]")
        }
        :set ipv4content [:toarray $ipv4content]
        :log info "[$scriptname] Finished replacing carriage returns."

        :set ipv4content [:toarray $finalContent]

        # Remove existing "DoH Servers" address list
        :log info "[$scriptname] Clearing address list ($ipv4list)"
        /ip firewall address-list remove [find list="$ipv4list"]

        # Add unique IPs to the "DoH Servers" address list
        :log info "[$scriptname] Adding unique IPs to the address list."
        :global uniqueIps [:toarray ""]
        :foreach ip in=$ipv4content do={
            :if ([:len $ip] > 0) do={
                :if ([:find $uniqueIps $ip] = -1) do={
                    :log info "[$scriptname] Adding IP to '$ipv4list' ($ip)"
                    /ip firewall address-list add list="$ipv4list" address="$ip" comment="[$scriptname] ipv4list"
                    :set uniqueIps ($uniqueIps, $ip)
                }
            }
        }

        # Redirect all port 53 DNS (DoH) traffic to router
        :log info "[$scriptname] Checking / Creating port 53 (DNS) redirect NAT rules."
        /ip firewall nat
        :if ([:len [find chain=dstnat dst-port="53" protocol="udp" action=redirect]] = 0) do={
            add action=redirect chain=dstnat dst-port="53" protocol="udp" to-ports="53" comment="[$scriptname] Redirect DNS - UDP"
            :log info "[$scriptname] Added a new Firewall rule to redirect DoH (UDP)"
        }
        :if ([:len [find chain=dstnat dst-port="53" protocol="tcp" action=redirect]] = 0) do={
            add action=redirect chain=dstnat dst-port="53" protocol="tcp" to-ports="53" comment="[$scriptname] Redirect DNS - TCP"
            :log info "[$scriptname] Added a new Firewall rule to redirect DoH (TCP)"
        }

        # Go into the Firewall Filter section
        /ip firewall filter
        :global firstforward [:pick [find chain=forward action!=passthrough ]]

        # Block all port 853 DNS (DoT/DoQ) traffic
        :if ([:len [find chain=forward protocol="tcp" dst-port="853" action=drop]] = 0) do={
            :global newrule [add chain=forward protocol=tcp dst-port=853 action=drop comment="[$scriptname] Block DoH - TCP"]
            move $newrule $firstforward
        }
        :if ([:len [find chain=forward protocol="udp" dst-port="853" action=drop]] = 0) do={
            :global newrule [add chain=forward protocol=udp dst-port=853 action=drop comment="[$scriptname] Block DoH - UDP"]
            move $newrule $firstforward
        }
        # Add firewall rule to block DoH via address list
        :if ([:len [find chain=forward dst-address-list=$ipv4list action=drop]] = 0) do={
            :global newrule [add action=drop chain=forward dst-address-list=$ipv4list comment="[$scriptname] Block DoH - Address List" ]
            move $newrule $firstforward
        }
    } else={
        :log error "[$scriptname] IP list file too large (>64KiB)"
    }
} else={
    :log error "[$scriptname] Download failed"
}
