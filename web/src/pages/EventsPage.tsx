import { useState } from 'react'
import EventTable from '../components/EventTable'
import { Card, ErrorBox, Pager, RefreshButton } from '../components/ui'
import { useI18n } from '../i18n'
import { api, type EventCategory } from '../lib/api'
import { useFetch } from '../lib/useFetch'

const PAGE_SIZE = 50

export default function EventsPage({ category, detector }: { category?: EventCategory; detector?: string }) {
  const { t } = useI18n()
  const [page, setPage] = useState(0)
  const { data, error, loading, reload } = useFetch(
    (s) => api.listEvents({ category, detector, limit: PAGE_SIZE, offset: page * PAGE_SIZE }, s),
    [category, detector, page],
  )
  const lastPage = data ? Math.max(0, Math.ceil(data.total / PAGE_SIZE) - 1) : 0

  return (
    <Card
      title={data ? t('common.total', { count: data.total }) : t('common.loading')}
      actions={<RefreshButton onClick={reload} loading={loading} />}
    >
      {error ? (
        <ErrorBox error={error} />
      ) : data ? (
        <>
          <EventTable items={data.items} showCategory={!category} />
          <Pager page={page} lastPage={lastPage} onChange={setPage} />
        </>
      ) : null}
    </Card>
  )
}
