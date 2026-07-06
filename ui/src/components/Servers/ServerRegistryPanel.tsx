import { Button } from '../common/Button'
import { Badge } from '../common/Badge'
import { Card } from '../common/Card'
import type { MCPServer } from '@/types'
import '../AdminPanel/AdminPanel.css'

const MOCK_SERVERS: MCPServer[] = [
  { server_id: 's1', name: 'poc-echo-server', upstream_url: 'http://mcp-echo:8000', status: 'approved', owner_sub: 'poc-seeder', injection_mode: 'none', created_at: '2026-06-04T10:00:00Z', approved_at: '2026-06-04T10:01:00Z' },
  { server_id: 's2', name: 'poc-notes-server', upstream_url: 'http://mcp-notes:8000', status: 'approved', owner_sub: 'poc-seeder', injection_mode: 'user', created_at: '2026-06-04T10:00:00Z', approved_at: '2026-06-04T10:01:00Z' },
  { server_id: 's3', name: 'poc-search-server', upstream_url: 'http://mcp-search:8000', status: 'approved', owner_sub: 'poc-seeder', injection_mode: 'service', created_at: '2026-06-04T10:00:00Z', approved_at: '2026-06-04T10:01:00Z' },
  { server_id: 's4', name: 'corp-jira-mcp', upstream_url: 'http://jira-mcp:8080', status: 'pending', owner_sub: 'bob@corp', injection_mode: 'none', created_at: '2026-06-04T14:30:00Z', approved_at: null },
]

export function ServerRegistryPanel() {
  const servers = MOCK_SERVERS
  const pending = servers.filter(s => s.status === 'pending')
  return (
    <div className="server-registry animate-in">
      {pending.length > 0 && (
        <div className="pending-banner">
          <span>⚠</span>
          <span><strong>{pending.length}</strong> server{pending.length > 1 ? 's' : ''} awaiting approval</span>
        </div>
      )}
      <Card padded={false}>
        <div className="section-header">
          <h2 className="section-title">Registered Servers</h2>
          <Button variant="primary" size="sm">+ Register</Button>
        </div>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Upstream URL</th>
              <th>Injection</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {servers.map(s => (
              <tr key={s.server_id}>
                <td><code className="mono-sm">{s.name}</code></td>
                <td><code className="mono-sm">{s.upstream_url}</code></td>
                <td><Badge label={s.injection_mode} variant="neutral" /></td>
                <td>
                  <Badge
                    label={s.status}
                    variant={s.status === 'approved' ? 'low' : s.status === 'pending' ? 'medium' : 'critical'}
                    dot
                  />
                </td>
                <td>
                  <div className="row-actions">
                    {s.status === 'pending' && <Button size="sm" variant="primary">Approve</Button>}
                    <Button size="sm" variant="ghost">Edit</Button>
                    {s.status === 'approved' && <Button size="sm" variant="danger">Suspend</Button>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  )
}
