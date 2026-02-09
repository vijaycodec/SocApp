'use client'

import { FC } from 'react'
import {
  ExclamationTriangleIcon,
  ClockIcon,
  ShieldCheckIcon,
  ServerIcon,
  ChartBarIcon,
  DocumentTextIcon,
  BoltIcon
} from '@heroicons/react/24/outline'

// 1. Add your type definition at the top
export type DashboardMetrics = {
  active_agents: number
  alerts_last_24hr: number
  avg_response_time: string
  compliance_score: number
  critical_alerts: number
  open_tickets: number
  resolved_today: number
  total_alerts: number
  total_events?: number
  total_logs?: number
  events_per_sec?: number
  logs_per_sec?: number
}

// 2. Accept `data` as props and use it in your cards
type StatsOverviewProps = {
  data: DashboardMetrics | null
}

export const StatsOverview: FC<StatsOverviewProps> = ({ data }) => {

  if (!data) {
    return <div className="text-sm text-gray-500">Loading stats...</div>
  }

  // Format rate values for display
  const formatRate = (rate?: number): string => {
    if (rate === undefined || rate === null) return '0'
    if (rate >= 1000) return `${(rate / 1000).toFixed(1)}K`
    if (rate >= 1) return rate.toFixed(1)
    if (rate >= 0.01) return rate.toFixed(2)
    return rate.toFixed(3)
  }

  const stats = [
    {
      name: 'Total Alerts (All-time)',
      value: data.total_alerts,
      change: '+12%',
      changeType: 'increase',
      icon: ExclamationTriangleIcon,
      color: 'text-blue-600 dark:text-blue-400',
      bgColor: 'bg-blue-100 dark:bg-blue-900/30',
      gradientFrom: 'from-blue-50 dark:from-blue-900/20',
      gradientTo: 'to-blue-100/50 dark:to-blue-800/10',
      borderColor: 'border-blue-200/50 dark:border-blue-800/30',
      viewDetailsLink: '/alerts'
    },
    {
      name: 'Alerts Last 24h',
      value: data.alerts_last_24hr,
      change: '-8%',
      changeType: 'decrease',
      icon: ClockIcon,
      color: 'text-orange-600 dark:text-orange-400',
      bgColor: 'bg-orange-100 dark:bg-orange-900/30',
      gradientFrom: 'from-orange-50 dark:from-orange-900/20',
      gradientTo: 'to-orange-100/50 dark:to-orange-800/10',
      borderColor: 'border-orange-200/50 dark:border-orange-800/30',
      viewDetailsLink: '/alerts'
    },
    {
      name: 'Compliance Score',
      value: data.compliance_score,
      change: '+2%',
      changeType: 'increase',
      icon: ShieldCheckIcon,
      color: 'text-purple-600 dark:text-purple-400',
      bgColor: 'bg-purple-100 dark:bg-purple-900/30',
      gradientFrom: 'from-purple-50 dark:from-purple-900/20',
      gradientTo: 'to-purple-100/50 dark:to-purple-800/10',
      borderColor: 'border-purple-200/50 dark:border-purple-800/30',
      viewDetailsLink: '/compliance'
    },
    {
      name: 'Active Agents',
      value: data.active_agents,
      change: '+3',
      changeType: 'increase',
      icon: ServerIcon,
      color: 'text-green-600 dark:text-green-400',
      bgColor: 'bg-green-100 dark:bg-green-900/30',
      gradientFrom: 'from-green-50 dark:from-green-900/20',
      gradientTo: 'to-green-100/50 dark:to-green-800/10',
      borderColor: 'border-green-200/50 dark:border-green-800/30',
      viewDetailsLink: '/agents'
    },
    {
      name: 'Total Events',
      value: data.total_events ?? 0,
      change: '',
      changeType: 'increase',
      icon: ChartBarIcon,
      color: 'text-cyan-600 dark:text-cyan-400',
      bgColor: 'bg-cyan-100 dark:bg-cyan-900/30',
      gradientFrom: 'from-cyan-50 dark:from-cyan-900/20',
      gradientTo: 'to-cyan-100/50 dark:to-cyan-800/10',
      borderColor: 'border-cyan-200/50 dark:border-cyan-800/30',
      viewDetailsLink: '/events-by-agent'
    },
    {
      name: 'Events / sec',
      value: formatRate(data.events_per_sec),
      change: '',
      changeType: 'increase',
      icon: BoltIcon,
      color: 'text-emerald-600 dark:text-emerald-400',
      bgColor: 'bg-emerald-100 dark:bg-emerald-900/30',
      gradientFrom: 'from-emerald-50 dark:from-emerald-900/20',
      gradientTo: 'to-emerald-100/50 dark:to-emerald-800/10',
      borderColor: 'border-emerald-200/50 dark:border-emerald-800/30',
      viewDetailsLink: '/events-by-agent'
    },
    {
      name: 'Logs / sec',
      value: formatRate(data.logs_per_sec),
      change: '',
      changeType: 'increase',
      icon: BoltIcon,
      color: 'text-violet-600 dark:text-violet-400',
      bgColor: 'bg-violet-100 dark:bg-violet-900/30',
      gradientFrom: 'from-violet-50 dark:from-violet-900/20',
      gradientTo: 'to-violet-100/50 dark:to-violet-800/10',
      borderColor: 'border-violet-200/50 dark:border-violet-800/30',
      viewDetailsLink: '/logs-by-agent'
    },
    {
      name: 'Total Logs',
      value: data.total_logs ?? 0,
      change: '',
      changeType: 'increase',
      icon: DocumentTextIcon,
      color: 'text-indigo-600 dark:text-indigo-400',
      bgColor: 'bg-indigo-100 dark:bg-indigo-900/30',
      gradientFrom: 'from-indigo-50 dark:from-indigo-900/20',
      gradientTo: 'to-indigo-100/50 dark:to-indigo-800/10',
      borderColor: 'border-indigo-200/50 dark:border-indigo-800/30',
      viewDetailsLink: '/logs-by-agent'
    },
  ]

  // Split stats into two rows: first 4 cards, then remaining 2 cards
  const firstRowStats = stats.slice(0, 4)
  const secondRowStats = stats.slice(4)

  const renderCard = (item: typeof stats[0]) => (
    <div
      key={item.name}
      className={`relative overflow-hidden rounded-xl bg-gradient-to-br from-white to-gray-50 dark:from-gray-800 dark:to-gray-900 px-5 pb-12 pt-5 shadow-md border ${item.borderColor} hover:shadow-lg transition-all duration-200 sm:px-6 sm:pt-6 backdrop-blur-sm`}
    >
      <dt>
        <div className={`absolute rounded-xl p-3 ${item.bgColor} bg-gradient-to-br ${item.gradientFrom} ${item.gradientTo} shadow-sm border ${item.borderColor}`}>
          <item.icon className={`h-6 w-6 ${item.color}`} aria-hidden="true" />
        </div>
        <p className="ml-16 truncate text-sm font-medium text-gray-500 dark:text-gray-400">
          {item.name}
        </p>
      </dt>
      <dd className="ml-16 flex items-baseline pb-6 sm:pb-7">
        <p className="text-2xl font-bold text-gray-900 dark:text-white">
          {item.value}
        </p>
        <div className={`absolute inset-x-0 bottom-0 bg-gradient-to-r ${item.gradientFrom} ${item.gradientTo} px-5 py-3 sm:px-6 border-t ${item.borderColor}`}>
          <div className="text-sm">
            <a href={item.viewDetailsLink} className={`font-medium ${item.color} hover:opacity-80 flex items-center justify-between`}>
              <span>View details</span>
              <svg className="h-4 w-4 ml-1" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clipRule="evenodd" />
              </svg>
              <span className="sr-only"> for {item.name}</span>
            </a>
          </div>
        </div>
      </dd>
    </div>
  )

  return (
    <div className="space-y-5">
      {/* First row: 4 cards */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        {firstRowStats.map(renderCard)}
      </div>
      {/* Second row: 4 cards (Total Events, Events/sec, Logs/sec, Total Logs) */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        {secondRowStats.map(renderCard)}
      </div>
    </div>
  )
} 