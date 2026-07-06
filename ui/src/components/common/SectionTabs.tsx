export interface SectionTabDef<T extends string> {
  id: T
  label: string
  count?: number
}

interface Props<T extends string> {
  tabs: SectionTabDef<T>[]
  active: T
  onChange: (id: T) => void
}

export function SectionTabs<T extends string>({ tabs, active, onChange }: Props<T>) {
  return (
    <div className="section-tabs" role="tablist">
      {tabs.map(t => (
        <button
          key={t.id}
          role="tab"
          aria-selected={active === t.id}
          className={`section-tab ${active === t.id ? 'section-tab--active' : ''}`}
          onClick={() => onChange(t.id)}
        >
          {t.label}
          {t.count !== undefined && <span className="section-tab__count">{t.count}</span>}
        </button>
      ))}
    </div>
  )
}
