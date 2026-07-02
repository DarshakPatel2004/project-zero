import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import ThreatSynthesisPanel from '../src/components/ThreatSynthesisPanel'

describe('ThreatSynthesisPanel', () => {
  test('renders "no data" when synthesis is null', () => {
    render(<ThreatSynthesisPanel synthesis={null} />)
    expect(screen.getByText(/No threat synthesis data/)).toBeTruthy()
  })

  test('renders score and risk level badge', () => {
    render(<ThreatSynthesisPanel synthesis={{ zero_day_risk_score: 72, risk_level: 'high', contributing_signals: [] }} />)
    expect(screen.getByText(/72/)).toBeTruthy()
    expect(screen.getByText(/HIGH/)).toBeTruthy()
  })

  test('renders contributing signals sorted by contribution', () => {
    const synthesis = {
      zero_day_risk_score: 85,
      risk_level: 'critical',
      contributing_signals: [
        { signal: 'binary_packing', contribution: 20, detail: 'DEX packing detected' },
        { signal: 'c2_endpoints', contribution: 15, detail: '3 C2 endpoints' },
      ],
    }
    render(<ThreatSynthesisPanel synthesis={synthesis} />)
    expect(screen.getByText('Binary Packing')).toBeTruthy()
    expect(screen.getByText('C2 Endpoints')).toBeTruthy()
  })

  test('shows critical level with rose badge', () => {
    render(<ThreatSynthesisPanel synthesis={{ zero_day_risk_score: 95, risk_level: 'critical', contributing_signals: [] }} />)
    const badge = screen.getByText(/CRITICAL/)
    expect(badge.className).toContain('badge-rose')
  })
})
