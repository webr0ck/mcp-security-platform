import { useState } from 'react'
import { SectionTabs } from '../common/SectionTabs'
import { Unauthorized } from '../common/Unauthorized'
import { ServerRegistryPanel } from './ServerRegistryPanel'
import { CredentialsPanel } from './CredentialsPanel'
import { SubmitServerWizard } from '../Submissions/SubmitServerWizard'
import { SubmissionReview } from '../Submissions/SubmissionReview'
import { useAuth } from '@/auth/AuthContext'

type ServerTab = 'registry' | 'review' | 'submit' | 'credentials'

const REVIEW_ROLES = ['admin', 'security_auditor', 'auditor']

export function ServersSection() {
  const [tab, setTab] = useState<ServerTab>('registry')
  const auth = useAuth()
  const isAdmin = auth.authenticated && auth.role === 'admin'
  const canReview = auth.authenticated && REVIEW_ROLES.includes(auth.role ?? '')

  return (
    <div className="section-page animate-in">
      <div className="section-page__header">
        <h1>Servers</h1>
        <p>Registry, review funnel, submission wizard and credentials — one server, one place.</p>
      </div>
      <SectionTabs<ServerTab>
        active={tab}
        onChange={setTab}
        tabs={[
          { id: 'registry', label: 'Registry' },
          { id: 'review', label: 'Review Queue' },
          { id: 'submit', label: 'Submit Server' },
          { id: 'credentials', label: 'Credentials' },
        ]}
      />
      {tab === 'registry' && (isAdmin ? <ServerRegistryPanel /> : <Unauthorized />)}
      {tab === 'review' && (canReview ? <SubmissionReview /> : <Unauthorized hint="Sign in with an admin, security_auditor, or auditor role." />)}
      {tab === 'submit' && <SubmitServerWizard />}
      {tab === 'credentials' && (isAdmin ? <CredentialsPanel /> : <Unauthorized />)}
    </div>
  )
}
