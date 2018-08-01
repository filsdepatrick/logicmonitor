import com.santaba.agent.groovyapi.http.*
import groovy.json.JsonSlurper
import groovy.json.JsonOutput

// Cisco Firepower Management Center

def isActiveDiscovery = true
def hostname = hostProps.get("system.hostname")
def user = hostProps.get("cfpmc.user")
def pass = hostProps.get("cfpmc.pass")
def instanceMap = [:]
def iLPs = ''
def cfpmc_auth_url = 'https://' + hostname + '/api/fmc_platform/v1/auth/generatetoken'
def cfpmc_rest_config_url = 'https://' + hostname + '/api/fmc_config/v1/domain/'
def encoded_auth = "${user}:${pass}".bytes.encodeBase64().toString()
// call method to get auth and refresh tokens as well as domain_uuid:
def token_list = get_tokens(cfpmc_auth_url, encoded_auth)
def auth_token = token_list[0]
def refresh_token = token_list[1]
def domain_uuid = token_list[2]
def healthStatus = 'unknown'

def healthStatusMap = [
'green'   : 0,
'disabled': 1,
'red'     : 2,
'unknown' : -1

]
try
{
    def httpClient = HTTP.open(hostname, 443)

    def response = httpClient.get(cfpmc_rest_config_url + domain_uuid + '/devices/devicerecords?expanded=true',
    ["X-auth-access-token": auth_token, "Domain_UUID": domain_uuid, "Content-Type": "application/json"])

    slurper = new JsonSlurper()
    devices = slurper.parseText(httpClient.getResponseBody())
//println JsonOutput.prettyPrint(httpClient.getResponseBody())

    devices.items.each
    { device ->
        instanceMap[device.id] = [device.name]
    }

    instanceMap.each
    { key, value ->
        iLPs = ''
        devices.items.each
        { device ->
            if (key.toString().equals(device.id))
            {
                healthStatus = device?.healthStatus ?: 'unknown'
                iLPs += 'auto.name=' + device.name + '&'
                iLPs += 'auto.model=' + device.model + '&'
                iLPs += 'auto.modelId=' + device.modelId + '&'
                iLPs += 'auto.modelNumber=' + device.modelNumber + '&'
                iLPs += 'auto.modelType=' + device.modelType + '&'
                iLPs += 'auto.sw_version=' + device.sw_version + '&'
                iLPs += 'auto.accessPolicy.name=' + device.accessPolicy.name + '&'
                iLPs += 'auto.healthPolicy.name=' + device.healthPolicy.name + '&'
                iLPs += 'auto.hostName=' + device.hostName + '&'
                iLPs += 'auto.license_capacities=' + device.license_caps

            }
        }
        if (isActiveDiscovery)
        {
            println key + '##' + value[0] + '##' + value[0] + '####' + iLPs
        }
        else
        {
            println key + '.healthStatus=' + healthStatusMap[healthStatus]
        }

    }
}
catch (Exception e)
{
    println e.getMessage()
    return 1
}
return 0
// method to retrieve auth and refresh tokens.  Pass it
// the url and the base64 encoded credentials
String[] get_tokens(url, auth)
{
    try
    {
        def results = []
        def result_keys = ['X-auth-access-token', 'X-auth-refresh-token', 'DOMAIN_UUID']
        def cfpmc_post = new URL(url).openConnection() as HttpURLConnection
        cfpmc_post.setRequestMethod("POST")
        cfpmc_post.setDoOutput(true)
        cfpmc_post.setRequestProperty("Content-Type", "application/json")
        cfpmc_post.setRequestProperty("Authorization", "Basic " + auth)
        cfpmc_post.setRequestProperty("Accept-Ranges", "bytes")
        def header_map = cfpmc_post.getHeaderFields()
        result_keys.each
        { result_key ->
            results.add(header_map[result_key].first())
        }

        //println cfpmc_post.getResponseCode()
        return results
    }
    catch (Exception e)
    {

        println e.getMessage()
        return 1
    }
}
