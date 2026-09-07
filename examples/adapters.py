"""Safe adapter demonstrations. No live network operations."""
from ddcar.adapters import mcp_action, http_action, github_action
from ddcar.crypto import sha256_digest

mcp=mcp_action('https://mcp.example.invalid','lookup',{'query':'hello'},b'{"type":"object"}')
http=http_action('POST','https://api.example.invalid/actions',b'{"amount":"10.00"}',{'content-type':'application/json'})
git=github_action('example/project','update-file',{'path':'README.md','content_digest':sha256_digest('new contents')},'0'*40)
if __name__=='__main__':
    for action in (mcp,http,git): print(action)
