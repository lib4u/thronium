"""Native group proxy editor, real core preview/start and reference protection."""
import json
import socket


def run(h):
    command,click,fill,select,wait_for,js,check,screenshot=(h[k] for k in ('command','click','fill','select','wait_for','js','check','screenshot'))
    request,base=h['request'],h['base'];initial=command('snapshot');geometry=request('GET',base+'/window/rect')
    source=command('saveGroup',{'name':'Group proxy fixtures'})['id']
    target=command('saveGroup',{'name':'Wrapped servers','subscription':{'url':'http://127.0.0.1:9/subscription','headers':{},'viaProxy':False,'inheritDefaults':False}})['id']
    def add(group,name,kind,config):return command('saveProfile',{'name':name,'groupId':group,'kind':kind,'config':config})['id']
    def rejected(name,payload,code):
        try:command(name,payload)
        except RuntimeError as e:return code in str(e)
        return False
    def close():click('#main-modal > .modal-head > button');wait_for('return !document.querySelector("dialog[open]")')
    def edit():
        click('.group-strip .icon-button');wait_for('return !!document.querySelector('+json.dumps('[data-group-edit="'+target+'"]')+')');click('[data-group-edit="'+target+'"]');wait_for('return !!document.querySelector("#group-chain-fields")')
        if not js('return document.querySelector("#group-chain-fields").open'):click('#group-chain-fields > summary')
    def save():click('#group-save');wait_for('return !!document.querySelector("#group-new")');close()
    try:
        command('disconnect')
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        command('preferences',{**initial['preferences'],'language':'en','theme':'dark','inboundPort':port})
        front=add(source,'Entry Xray','xray-outbound',{'protocol':'socks','settings':{'address':'127.0.0.1','port':9}})
        landing=add(source,'Exit sing-box','sing-box-outbound',{'type':'socks','server':'127.0.0.1','server_port':11})
        server=add(target,'Group server','sing-box-outbound',{'type':'socks','server':'127.0.0.1','server_port':10})
        full=add(target,'Complete JSON','sing-box-config',{'outbounds':[{'type':'direct'}]})
        endpoint=add(source,'Endpoint','sing-box-outbound',{'type':'tailscale'})
        wg_proxy=add(source,'WireGuard proxy','sing-box-outbound',{'type':'wireguard','private_key':'cHJpdmF0ZQ==','address':['10.177.43.2/32'],'peers':[{'address':'127.0.0.1','port':51820,'public_key':'cHVibGlj','allowed_ips':['0.0.0.0/0']}]})
        fullx=add(source,'Complete Xray','xray-config',{'inbounds':[{'tag':'user-in','protocol':'socks','listen':'127.0.0.1','port':1}],'outbounds':[{'tag':'exit','protocol':'freedom','settings':{}}],'routing':{'rules':[{'type':'field','inboundTag':['user-in'],'outboundTag':'exit'}]}})
        pool=add(source,'Pool','auto-selector',{'type':'auto-selector','members':[front,landing]})
        before=command('profile',{'id':server})['config']
        wait_for('return document.documentElement.lang==="en"&&[...document.querySelector(".group-strip select").options].some(o=>o.value==='+json.dumps(target)+')')
        edit();check(js('return document.querySelector("#group-chain-front").value===""&&document.querySelector("#group-chain-landing").value===""'),'group proxies default to None')
        candidates=js('return [...document.querySelector("#group-chain-front").options].map(o=>o.value)');check(front in candidates and landing in candidates and endpoint in candidates and all(p not in candidates for p in [full,pool]),'group proxy choices include outbound profiles and VPN endpoints and exclude full configurations and pools')
        landings=js('return [...document.querySelector("#group-chain-landing").options].map(o=>o.value)');check(fullx in candidates and fullx not in landings,'a complete Xray configuration is offered as the front proxy only')
        check(wg_proxy in candidates and wg_proxy in landings,'a userspace WireGuard endpoint is offered as front and landing proxy')
        check(rejected('saveGroup',{**command('group',{'id':target}),'proxyChain':{'front':front,'landing':fullx}},'group_chain_hop_unsupported'),'a complete Xray configuration is refused as the landing proxy')
        select('#group-chain-front',front);select('#group-chain-landing',landing);screenshot('group-chains-en');save()
        check(command('group',{'id':target})['proxyChain']=={'front':front,'landing':landing},'both group proxy references save together')
        check(command('profile',{'id':server})['config']==before,'saving a group route preserves the source server JSON')
        check(next(g for g in command('snapshot')['groups'] if g['id']==target)['proxyChain']['front']==front,'group snapshot exposes the configured reference without proxy credentials')
        command('checkProfile',command('profile',{'id':server}));check(True,'wrapped server validates through the real bundled cores')
        preview=command('connectionConfiguration',{'id':server,'active':False})
        check({p['name'] for p in preview['parts']}=={'sing-box','Xray'},'runtime preview contains the mixed core group chain')
        core=next(p['config'] for p in preview['parts'] if p['name']=='sing-box');check(next(p for p in core['outbounds'] if p['tag']=='proxy')['server_port']==11,'runtime exit points to the landing proxy')
        request('POST',base+'/refresh',{});wait_for('return !!document.querySelector(".add-connection")');edit();check(js('return [document.querySelector("#group-chain-front").value,document.querySelector("#group-chain-landing").value]')==[front,landing],'both selections survive a native webview reload');close()
        command('connect',{'id':server});active=command('snapshot');check(active['running']==server,'wrapped server starts the native core and local listener')
        with socket.create_connection(('127.0.0.1',port),timeout=2):pass
        check(rejected('connect',{'id':full},'group_chain_hop_unsupported') and command('snapshot')['running']==server,'incompatible wrapped full JSON leaves the existing connection running')
        edit();select('#group-chain-front','');click('#group-save');wait_for('return !!document.querySelector(".groups-modal [role=alert]")');check(command('group',{'id':target})['proxyChain']['front']==front and 'Disconnect' in js('return document.querySelector(".groups-modal [role=alert]").textContent'),'active group route changes are rejected and explained in the UI');close()
        draft=command('profile',{'id':front});draft['name']='Changed';check(rejected('saveProfile',draft,'stop_before_editing'),'active group protects a referenced proxy from edits')
        command('disconnect');check(rejected('deleteGroup',{'id':source,'deleteProfiles':True},'profile_used_in_group_chain'),'group deletion cannot remove proxies referenced by another group')
        check(rejected('deleteProfiles',{'ids':[server,landing]},'profile_used_in_group_chain') and command('profile',{'id':server})['config']==before,'bulk deletion with a group proxy fails atomically')
        command('preferences',{**command('snapshot')['preferences'],'language':'ru','theme':'light'});wait_for('return document.documentElement.lang==="ru"');edit();request('POST',base+'/window/rect',{'width':390,'height':720});
        check(js('const d=document.querySelector(".groups-modal"),b=d.querySelector(".modal-body");return b.scrollWidth<=b.clientWidth+1&&d.querySelector(".modal-footer").getBoundingClientRect().bottom<=innerHeight+1'),'Russian group proxy editor fits a narrow window');js('document.querySelector("#group-chain-fields").scrollIntoView({block:"end"})');screenshot('group-chains-ru-390')
        select('#group-chain-front','');select('#group-chain-landing','');save();check(command('group',{'id':target})['proxyChain']=={'front':None,'landing':None},'clearing both proxy choices restores a direct server route')
        check(command('group',{'id':target})['subscription']['url']=='http://127.0.0.1:9/subscription','editing group proxies preserves subscription settings')
    finally:
        command('disconnect');command('deleteGroup',{'id':target,'deleteProfiles':True});command('deleteGroup',{'id':source,'deleteProfiles':True});command('preferences',initial['preferences']);request('POST',base+'/window/rect',geometry)
