'use client'

import React, { useState, useEffect } from 'react'
import { useClient } from '@/contexts/ClientContext'
import { wazuhApi } from '@/lib/api'
import {
  ComputerDesktopIcon,
  ArrowPathIcon,
  MagnifyingGlassIcon,
  ChartBarSquareIcon,
  ExclamationTriangleIcon,
  ArrowUpIcon,
  ArrowDownIcon
} from '@heroicons/react/24/outline'
import { clsx } from 'clsx'

interface AgentEventData {
  agent_id: string
  agent_name: string
  agent_ip: string
  event_count: number
}

interface EventsByAgentResponse {
  agents: AgentEventData[]
  total_agents: number
  total_events: number
}

type SortField = 'agent_id' | 'agent_name' | 'agent_ip' | 'event_count'
type SortOrder = 'asc' | 'desc'

export default function EventsByAgentPage() {
  const { selectedClient } = useClient()
  const [data, setData] = useState<EventsByAgentResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [timeFilter, setTimeFilter] = useState<number | undefined>(undefined)
  const [sortField, setSortField] = useState<SortField>('event_count')
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc')

  const fetchData = async () => {
    setLoading(true)
    setError(null)
    try {
      const orgId = selectedClient?.id
      const response = await wazuhApi.getEventsCountByAgent(orgId, timeFilter, 100)
      const responseData = response.data || response
      setData(responseData)
    } catch (err: any) {
      console.error('Error fetching events by agent:', err)
      setError(err.message || 'Failed to fetch events by agent')
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

      if (sortField === 'event_count') {
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

  const getEventCountColor = (count: number, maxCount: number) => {
    const ratio = count / maxCount
    if (ratio > 0.7) return 'text-red-600 dark:text-red-400'
    if (ratio > 0.4) return 'text-yellow-600 dark:text-yellow-400'
    return 'text-green-600 dark:text-green-400'
  }

  const maxEventCount = React.useMemo(() => {
    if (!data?.agents?.length) return 1
    return Math.max(...data.agents.map(a => a.event_count || 0))
  }, [data])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <ChartBarSquareIcon className="h-7 w-7 text-blue-500" />
            Events By Agent
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            View event distribution across all agents/machines
          </p>
        </div>
        <button
          onClick={fetchData}
          disabled={loading}
          className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
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
                <ExclamationTriangleIcon className="h-6 w-6 text-purple-600 dark:text-purple-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Total Events</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {formatNumber(data.total_events)}
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
            className="w-full pl-10 pr-4 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
        {/* Time Filter */}
        <select
          value={timeFilter || ''}
          onChange={(e) => setTimeFilter(e.target.value ? Number(e.target.value) : undefined)}
          className="px-4 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
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
          <ArrowPathIcon className="h-8 w-8 text-blue-500 animate-spin" />
          <span className="ml-2 text-gray-600 dark:text-gray-400">Loading events data...</span>
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
                    onClick={() => handleSort('event_count')}
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800"
                  >
                    Event Count <SortIcon field="event_count" />
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Distribution
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {filteredAndSortedAgents.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
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
                          getEventCountColor(agent.event_count, maxEventCount)
                        )}>
                          {formatNumber(agent.event_count)}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="w-32 bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
                          <div
                            className={clsx(
                              'h-2.5 rounded-full transition-all duration-300',
                              agent.event_count / maxEventCount > 0.7 ? 'bg-red-500' :
                              agent.event_count / maxEventCount > 0.4 ? 'bg-yellow-500' : 'bg-green-500'
                            )}
                            style={{ width: `${(agent.event_count / maxEventCount) * 100}%` }}
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
