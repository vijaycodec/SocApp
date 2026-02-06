'use client'

import { useState, useEffect } from 'react'
import {
  BookOpenIcon,
  PlusIcon,
  PencilIcon,
  TrashIcon,
  ArrowDownTrayIcon,
  DocumentTextIcon,
  XMarkIcon,
  CheckCircleIcon,
  ClockIcon,
  ArchiveBoxIcon,
  EyeIcon
} from '@heroicons/react/24/outline'
import RichTextEditor from './components/RichTextEditor'

const BASE_URL = process.env.NEXT_PUBLIC_RBAC_BASE_IP

interface Sop {
  _id: string
  sop_name: string
  title: string
  description: string
  status: 'draft' | 'published' | 'archived'
  file_name: string | null
  file_size: number | null
  report_generated_at: string | null
  created_by?: { username: string; full_name: string }
  createdAt: string
  updatedAt: string
}

export default function PlaybooksSopsPage() {
  const [sops, setSops] = useState<Sop[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [showDetail, setShowDetail] = useState<Sop | null>(null)
  const [editingSop, setEditingSop] = useState<Sop | null>(null)
  const [formData, setFormData] = useState({ sop_name: '', title: '', description: '', status: 'draft' as const })
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [generatingId, setGeneratingId] = useState<string | null>(null)
  const [downloadingId, setDownloadingId] = useState<string | null>(null)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  useEffect(() => { fetchSops() }, [])
  useEffect(() => { if (message) { const t = setTimeout(() => setMessage(null), 3000); return () => clearTimeout(t) } }, [message])

  const fetchSops = async () => {
    try {
      setIsLoading(true)
      const token = localStorage.getItem('token')
      const res = await fetch(`${BASE_URL}/sops`, { headers: { 'Authorization': `Bearer ${token}` } })
      const data = await res.json()
      if (data.success) setSops(data.data.sops)
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to fetch SOPs' })
    } finally {
      setIsLoading(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)
    try {
      const token = localStorage.getItem('token')
      const url = editingSop ? `${BASE_URL}/sops/${editingSop._id}` : `${BASE_URL}/sops`
      const res = await fetch(url, {
        method: editingSop ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify(formData)
      })
      const data = await res.json()
      if (res.ok && data.success) {
        setMessage({ type: 'success', text: editingSop ? 'SOP updated!' : 'SOP created!' })
        fetchSops()
        resetForm()
      } else {
        setMessage({ type: 'error', text: data.message || 'Failed to save' })
      }
    } catch { setMessage({ type: 'error', text: 'Failed to save SOP' }) }
    finally { setIsSubmitting(false) }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this SOP?')) return
    try {
      const token = localStorage.getItem('token')
      const res = await fetch(`${BASE_URL}/sops/${id}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } })
      if (res.ok) { setMessage({ type: 'success', text: 'SOP deleted!' }); fetchSops() }
    } catch { setMessage({ type: 'error', text: 'Failed to delete' }) }
  }

  const handleGenerate = async (id: string) => {
    setGeneratingId(id)
    try {
      const token = localStorage.getItem('token')
      const res = await fetch(`${BASE_URL}/sops/${id}/generate-report`, { method: 'POST', headers: { 'Authorization': `Bearer ${token}` } })
      const data = await res.json()
      if (res.ok && data.success) { setMessage({ type: 'success', text: 'Report generated!' }); fetchSops() }
      else setMessage({ type: 'error', text: data.message || 'Failed to generate' })
    } catch { setMessage({ type: 'error', text: 'Failed to generate report' }) }
    finally { setGeneratingId(null) }
  }

  const handleDownload = async (id: string, fileName: string) => {
    setDownloadingId(id)
    try {
      const token = localStorage.getItem('token')
      const res = await fetch(`${BASE_URL}/sops/${id}/download`, { headers: { 'Authorization': `Bearer ${token}` } })
      const blob = await res.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = fileName; a.click()
      window.URL.revokeObjectURL(url)
    } catch { setMessage({ type: 'error', text: 'Failed to download' }) }
    finally { setDownloadingId(null) }
  }

  const resetForm = () => { setFormData({ sop_name: '', title: '', description: '', status: 'draft' }); setEditingSop(null); setShowForm(false) }
  const startEdit = (sop: Sop) => { setEditingSop(sop); setFormData({ sop_name: sop.sop_name, title: sop.title, description: sop.description, status: sop.status }); setShowForm(true) }
  const formatSize = (b: number | null) => b ? (b < 1024 * 1024 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1024 / 1024).toFixed(2)} MB`) : ''
  const formatDate = (d: string) => new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
  const statusStyles: Record<string, string> = { published: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400', draft: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400', archived: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400' }
  const statusIcons: Record<string, React.ReactNode> = { published: <CheckCircleIcon className="w-4 h-4" />, draft: <ClockIcon className="w-4 h-4" />, archived: <ArchiveBoxIcon className="w-4 h-4" /> }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <BookOpenIcon className="w-7 h-7 text-blue-600" /> Playbooks & SOPs
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">Manage Standard Operating Procedures</p>
        </div>
        <button onClick={() => setShowForm(true)} className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
          <PlusIcon className="w-5 h-5 mr-1" /> New SOP
        </button>
      </div>

      {/* Message */}
      {message && (
        <div className={`flex items-center p-3 rounded-lg ${message.type === 'success' ? 'bg-green-50 dark:bg-green-900/20 text-green-800 dark:text-green-200' : 'bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-200'}`}>
          {message.type === 'success' ? <CheckCircleIcon className="w-5 h-5 mr-2" /> : <XMarkIcon className="w-5 h-5 mr-2" />}
          {message.text}
        </div>
      )}

      {/* Form Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl w-full max-w-4xl max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="sticky top-0 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6 py-4 flex justify-between items-center">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">{editingSop ? 'Edit SOP' : 'Create SOP'}</h2>
              <button onClick={resetForm} className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"><XMarkIcon className="w-5 h-5" /></button>
            </div>
            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">SOP Name *</label>
                <input type="text" value={formData.sop_name} onChange={e => setFormData({ ...formData, sop_name: e.target.value })} required
                  className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500" placeholder="Enter SOP name" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Title *</label>
                <input type="text" value={formData.title} onChange={e => setFormData({ ...formData, title: e.target.value })} required
                  className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500" placeholder="Enter title" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Status</label>
                <select value={formData.status} onChange={e => setFormData({ ...formData, status: e.target.value as any })}
                  className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white">
                  <option value="draft">Draft</option>
                  <option value="published">Published</option>
                  <option value="archived">Archived</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Description *</label>
                <RichTextEditor value={formData.description} onChange={v => setFormData({ ...formData, description: v })} />
              </div>
              <div className="flex justify-end gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                <button type="button" onClick={resetForm} className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300">Cancel</button>
                <button type="submit" disabled={isSubmitting} className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50">
                  {isSubmitting ? 'Saving...' : editingSop ? 'Update' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Detail Modal */}
      {showDetail && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl w-full max-w-3xl max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="sticky top-0 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6 py-4 flex justify-between items-center">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">{showDetail.sop_name}</h2>
              <button onClick={() => setShowDetail(null)} className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"><XMarkIcon className="w-5 h-5" /></button>
            </div>
            <div className="p-6 space-y-4">
              <div className="flex items-center gap-2">
                <span className={`flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-full ${statusStyles[showDetail.status]}`}>
                  {statusIcons[showDetail.status]} {showDetail.status}
                </span>
                <span className="text-sm text-gray-500">Created {formatDate(showDetail.createdAt)}</span>
              </div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{showDetail.title}</h3>
              <div className="prose prose-sm dark:prose-invert max-w-none" dangerouslySetInnerHTML={{ __html: showDetail.description }} />
            </div>
          </div>
        </div>
      )}

      {/* Content */}
      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[1, 2, 3].map(i => <div key={i} className="bg-white dark:bg-gray-800 rounded-xl p-6 animate-pulse"><div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-3/4 mb-4" /><div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-full mb-2" /></div>)}
        </div>
      ) : sops.length === 0 ? (
        <div className="text-center py-16 bg-white dark:bg-gray-800 rounded-xl shadow">
          <BookOpenIcon className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium mb-2 text-gray-900 dark:text-white">No SOPs yet</h3>
          <p className="text-gray-500 mb-4">Create your first Standard Operating Procedure</p>
          <button onClick={() => setShowForm(true)} className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
            <PlusIcon className="w-5 h-5 inline mr-1" /> Create First SOP
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {sops.map(sop => (
            <div key={sop._id} className="bg-white dark:bg-gray-800 rounded-xl shadow border border-gray-200 dark:border-gray-700 overflow-hidden hover:shadow-lg transition-shadow">
              <div className="p-5 border-b border-gray-100 dark:border-gray-700">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                      <BookOpenIcon className="w-5 h-5 text-blue-600" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-gray-900 dark:text-white truncate">{sop.sop_name}</h3>
                      <p className="text-xs text-gray-500">{formatDate(sop.createdAt)}</p>
                    </div>
                  </div>
                  <span className={`flex items-center gap-1 px-2 py-1 text-xs font-medium rounded-full ${statusStyles[sop.status]}`}>
                    {statusIcons[sop.status]} {sop.status}
                  </span>
                </div>
              </div>
              <div className="p-5">
                <h4 className="font-medium text-gray-800 dark:text-gray-200 mb-2 line-clamp-2">{sop.title}</h4>
                <div className="text-sm text-gray-600 dark:text-gray-400 line-clamp-2 prose prose-sm dark:prose-invert max-w-none" dangerouslySetInnerHTML={{ __html: sop.description }} />

                {/* Report Card */}
                {sop.file_name && (
                  <div className="mt-4 p-3 bg-gradient-to-r from-green-50 to-emerald-50 dark:from-green-900/20 dark:to-emerald-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <DocumentTextIcon className="w-5 h-5 text-green-600" />
                        <div>
                          <p className="text-sm font-medium text-green-800 dark:text-green-200">Report Ready</p>
                          <p className="text-xs text-green-600 dark:text-green-400">{formatSize(sop.file_size)}</p>
                        </div>
                      </div>
                      <button
                        onClick={() => handleDownload(sop._id, sop.file_name!)}
                        disabled={downloadingId === sop._id}
                        className="flex items-center px-3 py-1.5 bg-green-600 text-white text-sm rounded-lg hover:bg-green-700 disabled:opacity-50"
                      >
                        {downloadingId === sop._id ? (
                          <><svg className="animate-spin w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>...</>
                        ) : (
                          <><ArrowDownTrayIcon className="w-4 h-4 mr-1" /> Download</>
                        )}
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Actions */}
              <div className="px-5 py-3 bg-gray-50 dark:bg-gray-900/50 border-t border-gray-100 dark:border-gray-700 flex flex-wrap gap-2">
                <button onClick={() => setShowDetail(sop)} className="flex items-center px-2 py-1 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded">
                  <EyeIcon className="w-4 h-4 mr-1" /> View
                </button>
                <button onClick={() => startEdit(sop)} className="flex items-center px-2 py-1 text-sm text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded">
                  <PencilIcon className="w-4 h-4 mr-1" /> Edit
                </button>
                <button onClick={() => handleDelete(sop._id)} className="flex items-center px-2 py-1 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/30 rounded">
                  <TrashIcon className="w-4 h-4 mr-1" /> Delete
                </button>
                <div className="flex-1" />
                <button
                  onClick={() => handleGenerate(sop._id)}
                  disabled={generatingId === sop._id}
                  className="flex items-center px-3 py-1 bg-purple-600 text-white text-sm rounded hover:bg-purple-700 disabled:opacity-50"
                >
                  {generatingId === sop._id ? (
                    <><svg className="animate-spin w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" /><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg> Generating...</>
                  ) : (
                    <><DocumentTextIcon className="w-4 h-4 mr-1" /> Generate Report</>
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
