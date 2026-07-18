import { useEffect, useRef } from 'react'
import type { ReactNode } from 'react'
import './Modal.css'

interface Props {
  title: string
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
  labelledBy?: string
}

// Minimal, dependency-free modal shared by admin-panel flows (server Edit,
// View logs, rebuild confirm, ...). Closes on Escape and on backdrop click;
// does not trap focus beyond returning it to the trigger isn't implemented —
// acceptable for an internal admin surface, but flag if this needs to be
// reused on a public-facing screen.
export function Modal({ title, onClose, children, footer }: Props) {
  const panelRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div
      className="modal-backdrop"
      onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="modal-panel" role="dialog" aria-modal="true" aria-label={title} ref={panelRef}>
        <div className="modal-panel__header">
          <h3>{title}</h3>
          <button type="button" className="modal-panel__close" aria-label="Close" onClick={onClose}>×</button>
        </div>
        <div className="modal-panel__body">{children}</div>
        {footer && <div className="modal-panel__footer">{footer}</div>}
      </div>
    </div>
  )
}
