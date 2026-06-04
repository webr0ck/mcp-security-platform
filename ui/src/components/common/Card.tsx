import type { HTMLAttributes } from 'react'
import './Card.css'

interface Props extends HTMLAttributes<HTMLDivElement> {
  glow?: boolean
  padded?: boolean
}

export function Card({ glow, padded = true, className = '', children, ...rest }: Props) {
  return (
    <div
      className={`card ${glow ? 'card--glow' : ''} ${padded ? 'card--padded' : ''} ${className}`}
      {...rest}
    >
      {children}
    </div>
  )
}

interface StatProps {
  label: string
  value: string | number
  delta?: string
  accent?: boolean
}

export function StatCard({ label, value, delta, accent }: StatProps) {
  return (
    <div className={`stat-card ${accent ? 'stat-card--accent' : ''}`}>
      <p className="stat-card__label">{label}</p>
      <p className="stat-card__value">{value}</p>
      {delta && <p className="stat-card__delta">{delta}</p>}
    </div>
  )
}
