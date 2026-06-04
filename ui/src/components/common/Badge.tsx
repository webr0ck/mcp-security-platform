import type { Severity } from '@/types'
import './Badge.css'

interface Props {
  label: string
  variant?: Severity | 'neutral' | 'accent'
  dot?: boolean
  pulse?: boolean
}

export function Badge({ label, variant = 'neutral', dot, pulse }: Props) {
  return (
    <span className={`badge badge--${variant}`}>
      {dot && <span className={`badge__dot${pulse ? ' badge__dot--pulse' : ''}`} />}
      {label}
    </span>
  )
}
