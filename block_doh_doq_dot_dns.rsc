:local scriptname "DoH block"
:local ipv4file "block_doh_dns/doh_ipv4.txt"
:local ipv4url "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/doh.txt"
:local ipv4list "DoH Servers"

:log info "[$scriptname] Downloading IP list"
:local result [/tool fetch url=$ipv4url mode=https dst-path=$ipv4file as-value]
:if ($result->"status" = "finished") do={
    :log info "[$scriptname] Downloaded IP list"

    :if ([/file get $ipv4file size] < 65536) do={
        :log info "[$scriptname] IP list file is smaller than 64KiB"
        :local ipv4content [/file get $ipv4file contents]

        # find newline and replace with comma to prepare data splitting with :toarray
        :local find "\n"
        :local replace ","
        :while condition=[find $ipv4content $find] do={
            :set ipv4content ("$[pick $ipv4content 0 ([find $ipv4content $find]) ]".$replace."$[pick $ipv4content ([find $ipv4content $find]+1) ([len $ipv4content])]")
        }
        # remove carriage returns
        :local find "\r"
        :local replace ""
        :while condition=[find $ipv4content $find] do={
            :set ipv4content ("$[pick $ipv4content 0 ([find $ipv4content $find]) ]".$replace."$[pick $ipv4content ([find $ipv4content $find]+1) ([len $ipv4content])]")
        }
        :set ipv4content [:toarray $ipv4content]

        # Remove existing "DoH Servers" address list
        :log info "[$scriptname] Clearing address list ($ipv4list)"
        /ip firewall address-list remove [find list="$ipv4list"]

        # Add unique IPs to the "DoH Servers" address list
        :local uniqueIps [:toarray ""]
        :foreach ip in=$ipv4content do={
            :log info "[$scriptname] Checking if IP is unique ($ip)"
            :if ([:find $uniqueIps $ip] != -1) do={
                :log info "[$scriptname] Adding IP to '$ipv4list' ($ip)"
                /ip firewall address-list add list="$ipv4list" address="$ip"
                :set uniqueIps ($uniqueIps, $ip)
            }
        }

        # Redirect all port 53 DNS (DoH) traffic to router
        /ip firewall nat
        :if ([:len [find chain=dstnat dst-port="53" protocol="udp" action=redirect]] = 0) do={
            add action=redirect chain=dstnat dst-port="53" protocol="udp" to-ports="53"
        }
        :if ([:len [find chain=dstnat dst-port="53" protocol="tcp" action=redirect]] = 0) do={
            add action=redirect chain=dstnat dst-port="53" protocol="tcp" to-ports="53"
        }

        # Find the highest priority forward rule
        /ip firewall filter
        :local firstforward [:pick [find chain=forward] 0]

        # Block all port 853 DNS (DoT/DoQ) traffic
        :if ([:len [find chain=forward protocol="tcp" dst-port="853" action=drop]] = 0) do={
            :local newrule [add chain=forward protocol=tcp dst-port=853 action=drop]
            move $newrule $firstforward
        }
        :if ([:len [find chain=forward protocol="udp" dst-port="853" action=drop]] = 0) do={
            :local newrule [add chain=forward protocol="udp" dst-port="853" action=drop]
            move $newrule $firstforward
        }
        # Add firewall rule to block DoH via address list
        :if ([:len [find chain=forward dst-address-list=$ipv4list action=drop]] = 0) do={
            :local newrule [add action=drop chain=forward comment="Drop DoH" dst-address-list=$ipv4list]
            move $newrule $firstforward
        }
        } else={
        :log error "[$scriptname] IP list file too large (>64KiB)"
        }
} else={
    :log error "[$scriptname] Download failed"
}
