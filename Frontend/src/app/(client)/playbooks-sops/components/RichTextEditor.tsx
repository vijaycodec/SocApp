'use client'

import { useEditor, EditorContent } from '@tiptap/react'
import StarterKit from '@tiptap/starter-kit'
import TextAlign from '@tiptap/extension-text-align'
import Underline from '@tiptap/extension-underline'
import HorizontalRule from '@tiptap/extension-horizontal-rule'
import Link from '@tiptap/extension-link'
import Placeholder from '@tiptap/extension-placeholder'
import Typography from '@tiptap/extension-typography'
import { useEffect, useState, useCallback } from 'react'

interface RichTextEditorProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
}

export default function RichTextEditor({ 
  value, 
  onChange, 
  placeholder = 'Start typing...' 
}: RichTextEditorProps) {
  const [isMounted, setIsMounted] = useState(false)
  const [linkUrl, setLinkUrl] = useState('')
  const [showLinkInput, setShowLinkInput] = useState(false)
  
  const editor = useEditor({
    extensions: [
      StarterKit.configure({
        heading: {
          levels: [1, 2, 3, 4],
        },
        codeBlock: {
          HTMLAttributes: {
            class: 'bg-gray-100 dark:bg-gray-800 p-4 rounded',
          },
        },
        bulletList: {
          HTMLAttributes: {
            class: 'list-disc pl-4',
          },
        },
        orderedList: {
          HTMLAttributes: {
            class: 'list-decimal pl-4',
          },
        },
        blockquote: {
          HTMLAttributes: {
            class: 'border-l-4 border-gray-300 dark:border-gray-600 pl-4 italic',
          },
        },
      }),
      Underline,
      HorizontalRule,
      Link.configure({
        openOnClick: false,
        HTMLAttributes: {
          class: 'text-blue-600 dark:text-blue-400 underline',
        },
      }),
      TextAlign.configure({
        types: ['heading', 'paragraph'],
      }),
      Placeholder.configure({
        placeholder,
      }),
      Typography,
    ],
    content: value,
    immediatelyRender: false,
    editorProps: {
      attributes: {
        class: 'prose prose-lg dark:prose-invert max-w-none focus:outline-none min-h-[300px] p-4',
      },
    },
    onUpdate: ({ editor }) => {
      onChange(editor.getHTML())
    },
  })

  useEffect(() => {
    setIsMounted(true)
  }, [])

  useEffect(() => {
    if (editor && value !== editor.getHTML()) {
      editor.commands.setContent(value)
    }
  }, [value, editor])

  const setLink = useCallback(() => {
    if (linkUrl === '') {
      editor?.chain().focus().unsetLink().run()
    } else {
      editor?.chain().focus().setLink({ href: linkUrl }).run()
    }
    setLinkUrl('')
    setShowLinkInput(false)
  }, [editor, linkUrl])

  const addImage = useCallback(() => {
    const url = window.prompt('Enter image URL:')
    if (url) {
      editor?.chain().focus().setImage({ src: url }).run()
    }
  }, [editor])

  if (!isMounted) {
    return (
      <div className="border border-gray-300 dark:border-gray-700 rounded-lg min-h-[300px] bg-gray-50 dark:bg-gray-800 animate-pulse" />
    )
  }

  if (!editor) {
    return (
      <div className="border border-gray-300 dark:border-gray-700 rounded-lg min-h-[300px] bg-gray-50 dark:bg-gray-800 animate-pulse" />
    )
  }

  return (
    <div className="border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden bg-white dark:bg-gray-900">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-1 p-2 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
        {/* Text Formatting */}
        <div className="flex items-center border-r border-gray-300 dark:border-gray-600 pr-2">
          <button
            type="button"
            onClick={() => editor.chain().focus().toggleBold().run()}
            className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive('bold') ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
            title="Bold"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 4h8a4 4 0 010 8H6zM6 12h9a4 4 0 010 8H6z" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => editor.chain().focus().toggleItalic().run()}
            className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive('italic') ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
            title="Italic"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 5h10M7 19h10m-4-7h2M9 12h2" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => editor.chain().focus().toggleUnderline().run()}
            className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive('underline') ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
            title="Underline"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 9v6a7 7 0 0014 0V9M12 19v-7M5 5h14" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => editor.chain().focus().toggleStrike().run()}
            className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive('strike') ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
            title="Strikethrough"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 12h14M12 5l-7 7 7 7" />
            </svg>
          </button>
        </div>

        {/* Headings */}
        <div className="flex items-center border-r border-gray-300 dark:border-gray-600 pr-2">
          <select
            className="p-1.5 bg-transparent border-none rounded text-sm hover:bg-gray-200 dark:hover:bg-gray-700"
            onChange={(e) => {
              const value = e.target.value
              if (value === 'paragraph') {
                editor.chain().focus().setParagraph().run()
              } else if (value.startsWith('h')) {
                const level = parseInt(value.replace('h', ''))
                editor.chain().focus().toggleHeading({ level }).run()
              }
            }}
            value={editor.isActive('heading') ? `h${editor.getAttributes('heading').level}` : 'paragraph'}
          >
            <option value="paragraph">Normal Text</option>
            <option value="h1">Heading 1</option>
            <option value="h2">Heading 2</option>
            <option value="h3">Heading 3</option>
            <option value="h4">Heading 4</option>
          </select>
        </div>

        {/* Lists */}
        <div className="flex items-center border-r border-gray-300 dark:border-gray-600 pr-2">
          <button
            type="button"
            onClick={() => editor.chain().focus().toggleBulletList().run()}
            className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive('bulletList') ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
            title="Bullet List"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => editor.chain().focus().toggleOrderedList().run()}
            className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive('orderedList') ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
            title="Numbered List"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
        </div>

        {/* Alignment */}
        <div className="flex items-center border-r border-gray-300 dark:border-gray-600 pr-2">
          <button
            type="button"
            onClick={() => editor.chain().focus().setTextAlign('left').run()}
            className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive({ textAlign: 'left' }) ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
            title="Align Left"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h8M4 18h16" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => editor.chain().focus().setTextAlign('center').run()}
            className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive({ textAlign: 'center' }) ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
            title="Align Center"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => editor.chain().focus().setTextAlign('right').run()}
            className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive({ textAlign: 'right' }) ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
            title="Align Right"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => editor.chain().focus().setTextAlign('justify').run()}
            className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive({ textAlign: 'justify' }) ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
            title="Justify"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
        </div>

        {/* Links & Media */}
        <div className="flex items-center border-r border-gray-300 dark:border-gray-600 pr-2">
          <div className="relative">
            <button
              type="button"
              onClick={() => setShowLinkInput(!showLinkInput)}
              className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive('link') ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
              title="Insert Link"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
              </svg>
            </button>
            
            {showLinkInput && (
              <div className="absolute top-full left-0 mt-1 p-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded shadow-lg z-10">
                <input
                  type="text"
                  value={linkUrl}
                  onChange={(e) => setLinkUrl(e.target.value)}
                  placeholder="Enter URL"
                  className="px-2 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      setLink()
                    }
                  }}
                />
                <div className="flex gap-1 mt-1">
                  <button
                    type="button"
                    onClick={setLink}
                    className="px-2 py-1 text-sm bg-blue-500 text-white rounded hover:bg-blue-600"
                  >
                    Apply
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowLinkInput(false)}
                    className="px-2 py-1 text-sm bg-gray-500 text-white rounded hover:bg-gray-600"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
          
          <button
            type="button"
            onClick={addImage}
            className="p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700"
            title="Insert Image"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
          </button>
        </div>

        {/* Blocks */}
        <div className="flex items-center border-r border-gray-300 dark:border-gray-600 pr-2">
          <button
            type="button"
            onClick={() => editor.chain().focus().toggleBlockquote().run()}
            className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive('blockquote') ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
            title="Blockquote"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => editor.chain().focus().toggleCodeBlock().run()}
            className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive('codeBlock') ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
            title="Code Block"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => editor.chain().focus().toggleCode().run()}
            className={`p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 ${editor.isActive('code') ? 'bg-gray-200 dark:bg-gray-700' : ''}`}
            title="Inline Code"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
          </button>
        </div>

        {/* Special Elements */}
        <div className="flex items-center">
          <button
            type="button"
            onClick={() => editor.chain().focus().setHorizontalRule().run()}
            className="p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700"
            title="Horizontal Rule"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 12H5" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => editor.chain().focus().clearNodes().run()}
            className="p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700"
            title="Clear Formatting"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2M3 12l6.414 6.414a2 2 0 001.414.586H19a2 2 0 002-2V7a2 2 0 00-2-2h-8.172a2 2 0 00-1.414.586L3 12z" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => editor.chain().focus().undo().run()}
            className="p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700"
            title="Undo"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => editor.chain().focus().redo().run()}
            className="p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700"
            title="Redo"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 10h-8a8 8 0 00-8 8v2M21 10l-6-6m6 6l-6 6" />
            </svg>
          </button>
        </div>
      </div>

      {/* Editor Content */}
      <div className="relative">
        <EditorContent editor={editor} className="min-h-[300px]" />
        
        {/* Word Count */}
        <div className="absolute bottom-2 right-2 text-xs text-gray-500 dark:text-gray-400 bg-white dark:bg-gray-800 px-2 py-1 rounded">
          {editor.storage.characterCount?.characters() || 0} characters
        </div>
      </div>
    </div>
  )
}