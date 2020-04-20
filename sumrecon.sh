
    url=$1
   
    basedir='/sumrecon/'

    echo 'Running scan for ' $url 

    echo "Initial Check to see if we can run this..."

    if [ ! -x "$(command -v assetfinder)" ]; then
        echo "[-] assetfinder required to run script"
        exit 1
    fi
    
    if [ ! -x "$(command -v amass)" ]; then
        echo "[-] amass required to run script"
        exit 1
    fi
    
    if [ ! -x "$(command -v sublist3r)" ]; then
        echo "[-] sublist3r required to run script"
        exit 1
    fi

    if [ ! -x "$(command -v gowitness)" ]; then
        echo "[-] gowitness required to run script"
        exit 1
    fi
 
    if [ ! -x "$(command -v httprobe)" ]; then
        echo "[-] httprobe required to run script"
        exit 1
    fi
    
    if [ ! -x "$(command -v waybackurls)" ]; then
        echo "[-] waybackurls required to run script"
        exit 1
    fi
    
    if [ ! -x "$(command -v whatweb)" ]; then
        echo "[-] whatweb required to run script"
        exit 1
    fi
    
    echo "Setting up the Directories..."

    if [ ! -d "$basedir$url" ];then
        mkdir $basedir$url
    fi
    if [ ! -d "$basedir$url/recon" ];then
        mkdir $basedir$url/recon
    fi
    if [ ! -d "$basedir$url/recon/gowitness" ]; then
    	mkdir $basedir$url/recon/gowitness
    fi
    if [ ! -d "$basedir$url/recon/3rd-lvls" ];then
        mkdir $basedir$url/recon/3rd-lvls
    fi
    if [ ! -d "$basedir$url/recon/scans" ];then
        mkdir $basedir$url/recon/scans
    fi
    if [ ! -d "$basedir$url/recon/httprobe" ];then
        mkdir $basedir$url/recon/httprobe
    fi
    if [ ! -d "$basedir$url/recon/potential_takeovers" ];then
        mkdir $basedir$url/recon/potential_takeovers
    fi
    if [ ! -d "$basedir$url/recon/wayback" ];then
        mkdir $basedir$url/recon/wayback
    fi
    if [ ! -d "$basedir$url/recon/wayback/params" ];then
        mkdir $basedir$url/recon/wayback/params
    fi
    if [ ! -d "$basedir$url/recon/wayback/extensions" ];then
        mkdir $basedir$url/recon/wayback/extensions
    fi
    if [ ! -d "$basedir$url/recon/whatweb" ];then
        mkdir $basedir$url/recon/whatweb
    fi
    if [ ! -f "$basedir$url/recon/httprobe/alive.txt" ];then
        touch $basedir$url/recon/httprobe/alive.txt
    fi
    if [ ! -f "$basedir$url/recon/final.txt" ];then
        touch $basedir$url/recon/final.txt
    fi
    if [ ! -f "$basedir$url/recon/3rd-lvl" ];then
        touch $basedir$url/recon/3rd-lvl-domains.txt
    fi
    
    echo "[+] Harvesting subdomains with assetfinder..."
    assetfinder $url | grep '.$url' | sort -u | tee -a $basedir$url/recon/final1.txt

    echo "[+] Double checking for subdomains with amass and certspotter..."
    amass enum -d $url | tee -a $basedir$url/recon/final1.txt
    curl -s https://certspotter.com/api/v0/certs\?domain\=$url | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | tee -a $basedir$url/recon/final1.txt
    sort -u $basedir$url/recon/final1.txt >> $basedir$url/recon/final.txt
    rm $basedir$url/recon/final1.txt
    
    echo "[+] Compiling 3rd lvl domains..."
    cat $basedir$url/recon/final.txt | grep -Po '(\w+\.\w+\.\w+)$' | sort -u >> $basedir$url/recon/3rd-lvl-domains.txt
    
    #write in line to recursively run thru final.txt
    for line in $(cat $basedir$url/recon/3rd-lvl-domains.txt);do 
	    echo $line | sort -u | tee -a $basedir$url/recon/final.txt;
    done
    
    echo "[+] Harvesting full 3rd lvl domains with sublist3r..."
    for domain in $(cat $basedir$url/recon/3rd-lvl-domains.txt);do 
	    sublist3r -d $domain -o $basedir$url/recon/3rd-lvls/$domain.txt;
    done
    
    echo "[+] Probing for alive domains..."
    cat $basedir$url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' | sort -u >> $basedir$url/recon/httprobe/alive.txt

    echo "[+] Checking for possible subdomain takeover..."
    
    if [ ! -f "$basedir$url/recon/potential_takeovers/domains.txt" ];then
        touch $basedir$url/recon/potential_takeovers/domains.txt
    fi
    if [ ! -f "$basedir$url/recon/potential_takeovers/potential_takeovers1.txt" ];then
        touch $basedir$url/recon/potential_takeovers/potential_takeovers1.txt
    fi

    for line in $(cat $basedir$url/recon/final.txt);do 
	    echo $line |sort -u >> $basedir$url/recon/potential_takeovers/domains.txt;
    done

    subjack -w $basedir$url/recon/httprobe/alive.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 >> $basedir$url/recon/potential_takeovers/potential_takeovers1.txt
    sort -u $basedir$url/recon/potential_takeovers/potential_takeovers1.txt >> $basedir$url/recon/potential_takeovers/potential_takeovers.txt
    rm $basedir$url/recon/potential_takeovers/potential_takeovers1.txt
    
    echo "[+] Running whatweb on compiled domains..."
    for domain in $(cat $basedir$url/recon/httprobe/alive.txt);do
        if [ ! -d  "$basedir$url/recon/whatweb/$domain" ];then
            mkdir $basedir$url/recon/whatweb/$domain
        fi
        if [ ! -d "$basedir$url/recon/whatweb/$domain/output.txt" ];then
            touch $basedir$url/recon/whatweb/$domain/output.txt
        fi
        if [ ! -d "$basedir$url/recon/whaweb/$domain/plugins.txt" ];then
            touch $basedir$url/recon/whatweb/$domain/plugins.txt
        fi
        
	    echo "[*] Pulling plugins data on $domain $(date +'%Y-%m-%d %T') "
        whatweb --info-plugins -t 50 -v $domain >> $basedir$url/recon/whatweb/$domain/plugins.txt; sleep 3
        
	    echo "[*] Running whatweb on $domain $(date +'%Y-%m-%d %T')"
        whatweb -t 50 -v $domain >> $basedir$url/recon/whatweb/$domain/output.txt; sleep 3
    done
    
    echo "[+] Scraping wayback data..."
    cat $basedir$url/recon/final.txt | waybackurls | tee -a  $basedir$url/recon/wayback/wayback_output1.txt
    sort -u $basedir$url/recon/wayback/wayback_output1.txt >> $basedir$url/recon/wayback/wayback_output.txt
    rm $basedir$url/recon/wayback/wayback_output1.txt
    
    echo "[+] Pulling and compiling all possible params found in wayback data..."
    cat $basedir$url/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $basedir$url/recon/wayback/params/wayback_params.txt
    for line in $(cat $basedir$url/recon/wayback/params/wayback_params.txt);do 
	    echo $line'=';
    done
    
    echo "[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output..."
    for line in $(cat $basedir$url/recon/wayback/wayback_output.txt);do
        ext="${line##*.}"
        if [[ "$ext" == "js" ]]; then
            echo $line | sort -u | tee -a $basedir$url/recon/wayback/extensions/js.txt
        fi
        if [[ "$ext" == "html" ]];then
            echo $line | sort -u | tee -a $basedir$url/recon/wayback/extensions/jsp.txt
        fi
        if [[ "$ext" == "json" ]];then
            echo $line | sort -u | tee -a $basedir$url/recon/wayback/extensions/json.txt
        fi
        if [[ "$ext" == "php" ]];then
            echo $line | sort -u | tee -a $basedir$url/recon/wayback/extensions/php.txt
        fi
        if [[ "$ext" == "aspx" ]];then
            echo $line | sort -u | tee -a $basedir$url/recon/wayback/extensions/aspx.txt
        fi
    done
    
    echo "[+] Scanning for open ports..."
    nmap -iL $basedir$url/recon/httprobe/alive.txt -T4 -oA $basedir$url/recon/scans/scanned.txt
    
    echo "[+] Running gowitness against all compiled domains..."
    gowitness file -s $basedir$url/recon/httprobe/alive.txt -d $basedir$url/recon/gowitness
