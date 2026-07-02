import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import AnalysisView, { riskLevelBadgeClass } from '../src/components/AnalysisView'

describe('riskLevelBadgeClass', () => {
  test('critical maps to badge-rose', () => {
    expect(riskLevelBadgeClass('critical')).toBe('badge-rose')
  })
  test('high maps to badge-rose', () => {
    expect(riskLevelBadgeClass('high')).toBe('badge-rose')
  })
  test('medium maps to badge-amber', () => {
    expect(riskLevelBadgeClass('medium')).toBe('badge-amber')
  })
  test('low maps to badge-emerald', () => {
    expect(riskLevelBadgeClass('low')).toBe('badge-emerald')
  })
  test('unknown maps to badge-slate', () => {
    expect(riskLevelBadgeClass('unknown')).toBe('badge-slate')
  })
  test('null/undefined maps to badge-slate', () => {
    expect(riskLevelBadgeClass(undefined)).toBe('badge-slate')
    expect(riskLevelBadgeClass(null)).toBe('badge-slate')
    expect(riskLevelBadgeClass('garbage')).toBe('badge-slate')
  })
})
