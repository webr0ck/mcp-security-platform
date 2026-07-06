import { useState } from 'react'
import { SectionTabs } from '../common/SectionTabs'
import { Unauthorized } from '../common/Unauthorized'
import { IdentitySettings } from './IdentitySettings'
import { InstallWizard } from '../Wizard/InstallWizard'
import { useAuth } from '@/auth/AuthContext'

type SettingsTab = 'identity' | 'setup'

export function SettingsSection() {
  const [tab, setTab] = useState<SettingsTab>('identity')
  const auth = useAuth()
  const isAdmin = auth.authenticated && auth.role === 'admin'

  return (
    <div className="section-page animate-in">
      <div className="section-page__header">
        <h1>Settings</h1>
        <p>Identity (OIDC) and platform setup.</p>
      </div>
      <SectionTabs<SettingsTab>
        active={tab}
        onChange={setTab}
        tabs={[
          { id: 'identity', label: 'Identity (OIDC)' },
          { id: 'setup', label: 'Setup' },
        ]}
      />
      {tab === 'identity' && (isAdmin ? <IdentitySettings /> : <Unauthorized />)}
      {tab === 'setup' && <InstallWizard />}
    </div>
  )
}
