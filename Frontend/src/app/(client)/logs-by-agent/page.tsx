'use client'

import React, { useState, useEffect } from 'react'
import { useClient } from '@/contexts/ClientContext'
import { wazuhApi } from '@/lib/api'
import {
  ComputerDesktopIcon,
  ArrowPathIcon,
  MagnifyingGlassIcon,
  DocumentTextIcon,
  ArrowUpIcon,
  ArrowDownIcon
} from '@heroicons/react/24/outline'
import { clsx } from 'clsx'

interface TrendPoint {
  timestamp: string
  count: number
}

interface AgentLogData {
  agent_id: string
  agent_name: string
  agent_ip: string
  log_count: number
  trend?: TrendPoint[]
}

interface LogsByAgentResponse {
  agents: AgentLogData[]
  total_agents: number
  total_logs: number
  trend_interval?: string
}

// Sparkline Chart Component
function SparklineChart({ data, width = 120, height = 32 }: { data: TrendPoint[], width?: number, height?: number }) {
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center text-gray-400 text-xs" style={{ width, height }}>
        No data
      </div>
    )
  }

  const counts = data.map(d => d.count)
  const maxVal = Math.max(...counts, 1)
  const minVal = Math.min(...counts)
  const range = maxVal - minVal || 1

  // Generate SVG path for the line
  const padding = 2
  const chartWidth = width - padding * 2
  const chartHeight = height - padding * 2

  const points = data.map((point, i) => {
    const x = padding + (i / (data.length - 1 || 1)) * chartWidth
    const y = padding + chartHeight - ((point.count - minVal) / range) * chartHeight
    return `${x},${y}`
  }).join(' ')

  // Create area path (for gradient fill)
  const areaPath = `M ${padding},${padding + chartHeight} ` +
    data.map((point, i) => {
      const x = padding + (i / (data.length - 1 || 1)) * chartWidth
      const y = padding + chartHeight - ((point.count - minVal) / range) * chartHeight
      return `L ${x},${y}`
    }).join(' ') +
    ` L ${padding + chartWidth},${padding + chartHeight} Z`

  // Determine trend color based on overall trend
  const firstHalf = counts.slice(0, Math.floor(counts.length / 2))
  const secondHalf = counts.slice(Math.floor(counts.length / 2))
  const firstAvg = firstHalf.reduce((a, b) => a + b, 0) / (firstHalf.length || 1)
  const secondAvg = secondHalf.reduce((a, b) => a + b, 0) / (secondHalf.length || 1)

  const isIncreasing = secondAvg > firstAvg * 1.1
  const isDecreasing = secondAvg < firstAvg * 0.9

  const strokeColor = isIncreasing ? '#ef4444' : isDecreasing ? '#22c55e' : '#a855f7'
  const fillColor = isIncreasing ? '#ef444420' : isDecreasing ? '#22c55e20' : '#a855f720'

  return (
    <svg width={width} height={height} className="overflow-visible">
      <defs>
        <linearGradient id={`gradient-${strokeColor}`} x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor={strokeColor} stopOpacity="0.3" />
          <stop offset="100%" stopColor={strokeColor} stopOpacity="0.05" />
        </linearGradient>
      </defs>
      {/* Area fill */}
      <path
        d={areaPath}
        fill={fillColor}
        strokeWidth="0"
      />
      {/* Line */}
      <polyline
        points={points}
        fill="none"
        stroke={strokeColor}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Last point dot */}
      {data.length > 0 && (
        <circle
          cx={padding + chartWidth}
          cy={padding + chartHeight - ((counts[counts.length - 1] - minVal) / range) * chartHeight}
          r="2.5"
          fill={strokeColor}
        />
      )}
    </svg>
  )
}

type SortField = 'agent_id' | 'agent_name' | 'agent_ip' | 'log_count'
type SortOrder = 'asc' | 'desc'

export default function LogsByAgentPage() {
  const { selectedClient } = useClient()
  const [data, setData] = useState<LogsByAgentResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [timeFilter, setTimeFilter] = useState<number | undefined>(undefined)
  const [sortField, setSortField] = useState<SortField>('log_count')
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc')

  const fetchData = async () => {
    setLoading(true)
    setError(null)
    try {
      const orgId = selectedClient?.id
      const response = await wazuhApi.getLogsCountByAgent(orgId, timeFilter, 100)
      setData(response.data || response)
    } catch (err: any) {
      console.error('Error fetching logs by agent:', err)
      setError(err.message || 'Failed to fetch logs by agent')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [selectedClient, timeFilter])

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortOrder('desc')
    }
  }

  const filteredAndSortedAgents = React.useMemo(() => {
    if (!data?.agents) return []

    let filtered = data.agents.filter(agent =>
      agent.agent_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      agent.agent_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      agent.agent_ip?.toLowerCase().includes(searchTerm.toLowerCase())
    )

    filtered.sort((a, b) => {
      let aVal: any = a[sortField]
      let bVal: any = b[sortField]

      if (sortField === 'log_count') {
        aVal = Number(aVal) || 0
        bVal = Number(bVal) || 0
      } else {
        aVal = String(aVal || '').toLowerCase()
        bVal = String(bVal || '').toLowerCase()
      }

      if (sortOrder === 'asc') {
        return aVal > bVal ? 1 : -1
      } else {
        return aVal < bVal ? 1 : -1
      }
    })

    return filtered
  }, [data, searchTerm, sortField, sortOrder])

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return null
    return sortOrder === 'asc' ? (
      <ArrowUpIcon className="h-4 w-4 inline ml-1" />
    ) : (
      <ArrowDownIcon className="h-4 w-4 inline ml-1" />
    )
  }

  const formatNumber = (num: number) => {
    return new Intl.NumberFormat().format(num)
  }

  const getLogCountColor = (count: number, maxCount: number) => {
    const ratio = count / maxCount
    if (ratio > 0.7) return 'text-red-600 dark:text-red-400'
    if (ratio > 0.4) return 'text-yellow-600 dark:text-yellow-400'
    return 'text-green-600 dark:text-green-400'
  }

  const maxLogCount = React.useMemo(() => {
    if (!data?.agents?.length) return 1
    return Math.max(...data.agents.map(a => a.log_count || 0))
  }, [data])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <DocumentTextIcon className="h-7 w-7 text-purple-500" />
            Logs (Archives)
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            View logs distribution across all agents/machines
          </p>
        </div>
        <button
          onClick={fetchData}
          disabled={loading}
          className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 transition-colors"
        >
          <ArrowPathIcon className={clsx('h-5 w-5', loading && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {/* Summary Cards */}
      {data && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                <ComputerDesktopIcon className="h-6 w-6 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Total Agents</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {formatNumber(data.total_agents)}
                </p>
              </div>
            </div>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-3">
              <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
                <DocumentTextIcon className="h-6 w-6 text-purple-600 dark:text-purple-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Total Logs</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {formatNumber(data.total_logs)}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        {/* Search */}
        <div className="relative flex-1">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search by agent name, ID, or IP..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-purple-500 focus:border-transparent"
          />
        </div>
        {/* Time Filter */}
        <select
          value={timeFilter || ''}
          onChange={(e) => setTimeFilter(e.target.value ? Number(e.target.value) : undefined)}
          className="px-4 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-purple-500 focus:border-transparent"
        >
          <option value="">All Time</option>
          <option value="1">Last 1 Hour</option>
          <option value="6">Last 6 Hours</option>
          <option value="24">Last 24 Hours</option>
          <option value="168">Last 7 Days</option>
          <option value="720">Last 30 Days</option>
        </select>
      </div>

      {/* Error State */}
      {error && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
          <p className="text-red-600 dark:text-red-400">{error}</p>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <ArrowPathIcon className="h-8 w-8 text-purple-500 animate-spin" />
          <span className="ml-2 text-gray-600 dark:text-gray-400">Loading logs data...</span>
        </div>
      )}

      {/* Table */}
      {!loading && !error && data && (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-900/50">
                <tr>
                  <th
                    onClick={() => handleSort('agent_id')}
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800"
                  >
                    Agent ID <SortIcon field="agent_id" />
                  </th>
                  <th
                    onClick={() => handleSort('agent_name')}
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800"
                  >
                    Agent Name <SortIcon field="agent_name" />
                  </th>
                  <th
                    onClick={() => handleSort('agent_ip')}
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800"
                  >
                    IP Address <SortIcon field="agent_ip" />
                  </th>
                  <th
                    onClick={() => handleSort('log_count')}
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800"
                  >
                    Log Count <SortIcon field="log_count" />
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Trend
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Distribution
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {filteredAndSortedAgents.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                      {searchTerm ? 'No agents match your search' : 'No agents found'}
                    </td>
                  </tr>
                ) : (
                  filteredAndSortedAgents.map((agent) => (
                    <tr key={agent.agent_id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                          {agent.agent_id}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <ComputerDesktopIcon className="h-5 w-5 text-gray-400" />
                          <span className="text-sm font-medium text-gray-900 dark:text-white">
                            {agent.agent_name || 'Unknown'}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-sm text-gray-600 dark:text-gray-300 font-mono">
                          {agent.agent_ip || 'N/A'}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={clsx(
                          'text-sm font-semibold',
                          getLogCountColor(agent.log_count, maxLogCount)
                        )}>
                          {formatNumber(agent.log_count)}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <SparklineChart data={agent.trend || []} />
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="w-32 bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
                          <div
                            className={clsx(
                              'h-2.5 rounded-full transition-all duration-300',
                              agent.log_count / maxLogCount > 0.7 ? 'bg-red-500' :
                              agent.log_count / maxLogCount > 0.4 ? 'bg-yellow-500' : 'bg-green-500'
                            )}
                            style={{ width: `${(agent.log_count / maxLogCount) * 100}%` }}
                          />
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {/* Footer */}
          <div className="px-6 py-3 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/50">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Showing {filteredAndSortedAgents.length} of {data.total_agents} agents
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
