import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'

vi.stubGlobal('fetch', vi.fn())

const mockOkJson = (data) => ({
  ok: true,
  json: async () => data,
})

beforeEach(() => {
  vi.clearAllMocks()
  fetch.mockResolvedValue(mockOkJson({ obfuscation_score: 0, techniques: [] }))
})

describe('ObfuscationView augmented cards', () => {
  test('renders packing card when binary_packing data exists', async () => {
    const ObfuscationView = (await import('../src/components/ObfuscationView')).default
    render(
      <ObfuscationView
        sample={{ sha256: 'abc' }}
        apiUrl="http://localhost:8000"
        result={{
          binary_packing: { packer_detected: true, packer_name: 'UPX', entropy: 7.5 },
        }}
      />
    )
    await waitFor(() => {
      expect(screen.getByText('Binary Packing')).toBeTruthy()
    })
    expect(screen.getByText(/UPX/)).toBeTruthy()
  })

  test('renders reflective calls card when data exists', async () => {
    const ObfuscationView = (await import('../src/components/ObfuscationView')).default
    render(
      <ObfuscationView
        sample={{ sha256: 'abc' }}
        apiUrl="http://localhost:8000"
        result={{
          reflective_tracing: { has_reflection: true, call_count: 15 },
        }}
      />
    )
    await waitFor(() => {
      expect(screen.getByText('Reflective Calls')).toBeTruthy()
    })
    expect(screen.getByText(/15/)).toBeTruthy()
  })

  test('does not render cards when no result data', async () => {
    const ObfuscationView = (await import('../src/components/ObfuscationView')).default
    render(
      <ObfuscationView
        sample={{ sha256: 'abc' }}
        apiUrl="http://localhost:8000"
        result={{}}
      />
    )
    await waitFor(() => {
      expect(document.querySelector('.obfuscation-view')).toBeTruthy()
    })
    expect(screen.queryByText('Binary Packing')).toBeNull()
    expect(screen.queryByText('Reflective Calls')).toBeNull()
  })
})
