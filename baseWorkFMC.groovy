import com.santaba.agent.groovyapi.http.*
import groovy.json.JsonSlurper
import groovy.json.JsonOutput
// Cisco Firepower Management Center
def hostname = hostProps.get("system.hostname")
def isActiveDiscovery = true
def user = hostProps.get("cfpmc.user")
def pass = hostProps.get("cfpmc.pass")
def encoded_auth = "${user}:${pass}".bytes.encodeBase64().toString()
def cfpmc_auth_url = 'https://' + hostname + '/api/fmc_platform/v1/auth/generatetoken'
def cfpmc_rest_info_url = 'https://' + hostname + '/api/fmc_platform/v1/info/'
def cfpmc_rest_config_url = 'https://' + hostname + '/api/fmc_config/v1/domain/'
// call method to retrieve auth, refresh tokens and domain_uuid:
def token_list = get_tokens(cfpmc_auth_url, encoded_auth)
def auth_token = token_list[0]
def refresh_token = token_list[1]
def domain_uuid = token_list[2]
def instanceMap = [:]
def interfaces
def statistics

//println "auth token: ${auth_token}"
//println "refresh token: ${refresh_token}"
//println "domain uuid: ${domain_uuid}"
println "using the LM http lib to make a server version query "

def httpClient = HTTP.open(hostname, 443)

def response = httpClient.get(cfpmc_rest_config_url + domain_uuid + '/devices/devicerecords',
    ["X-auth-access-token" : auth_token, "Domain_UUID" : domain_uuid, "Content-Type" : "application/json"])

slurper = new JsonSlurper()
devices = slurper.parseText(httpClient.getResponseBody())
//println JsonOutput.prettyPrint(httpClient.getResponseBody())

devices.items.each
{ device ->
    instanceMap[device.id] = [device.name]
    httpClient.get(cfpmc_rest_config_url + domain_uuid + '/devices/devicerecords/' + device.id + '/physicalinterfaces',
        ["X-auth-access-token" : auth_token, "Domain_UUID" : domain_uuid, "Content-Type" : "application/json"])
    interfaces = httpClient.getResponseBody()
    //interfaces = slurper.parseText(httpClient.getResponseBody())
    instanceMap[device.id] << interfaces
    httpClient.get(cfpmc_rest_config_url + domain_uuid + '/devices/devicerecords/' + device.id + '/fpinterfacestatistics',
        ["X-auth-access-token" : auth_token, "Domain_UUID" : domain_uuid, "Content-Type" : "application/json"])
    statistics = httpClient.getResponseBody()
    //statistics = slurper.parseText(httpClient.getResponseBody())
    instanceMap[device.id] << statistics

}

if (isActiveDiscovery)
{
    instanceMap.each
    {key, value ->
        println key + '##' + value[0] + '##' + value[0]
        println JsonOutput.prettyPrint(value[1])
        println JsonOutput.prettyPrint(value[2])

    }
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
        {
            results.add(header_map[it].first())
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
