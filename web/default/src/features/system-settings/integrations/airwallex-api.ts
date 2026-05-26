/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import { api } from '@/lib/api'

// Empty/undefined fields fall back to saved OptionMap values on the
// backend, so a returning admin can probe without retyping the API key.
export interface AirwallexTestRequest {
  client_id?: string
  api_key?: string
  sandbox?: boolean
}

export interface AirwallexTestResult {
  success: boolean
  auth_ok: boolean
  payment_link_ok: boolean
  host: string
  sandbox: boolean
  stage: 'config' | 'auth' | 'payment_link' | 'ok'
  message: string
  detail?: string
  probe_link?: string
}

export async function testAirwallexConnection(
  body: AirwallexTestRequest
): Promise<AirwallexTestResult> {
  const res = await api.post<AirwallexTestResult>(
    '/api/option/airwallex/test',
    body,
    { skipBusinessError: true } as Record<string, unknown>
  )
  return res.data
}
