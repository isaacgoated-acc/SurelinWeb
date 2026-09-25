import { withSupabase } from 'npm:@supabase/server@^1'

const json = (data: unknown, status = 200) =>
  Response.json(data, { status })

const secretKeys = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') ?? '{}')
const AUTH_SECRET = secretKeys.default ?? Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
const ITERATIONS = 310000
const TOKEN_TTL = 60 * 60 * 24 * 7

function b64url(input: Uint8Array | string) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

function fromB64url(value: string) {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4)
  const binary = atob(padded)
  return new Uint8Array([...binary].map((c) => c.charCodeAt(0)))
}

async function hmac(message: string) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(AUTH_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  )
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message)))
}

async function makeToken(userId: string) {
  const payload = b64url(JSON.stringify({ sub: userId, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL, v: 1 }))
  return `${payload}.${b64url(await hmac(payload))}`
}

async function verifyToken(token: string | null) {
  if (!token || !AUTH_SECRET) return null
  const parts = token.split('.')
  if (parts.length !== 2) return null
  const [payload, signature] = parts
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(AUTH_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  )
  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    fromB64url(signature),
    new TextEncoder().encode(payload),
  )
  if (!valid) return null
  const data = JSON.parse(new TextDecoder().decode(fromB64url(payload)))
  if (!data.sub || Number(data.exp) < Math.floor(Date.now() / 1000)) return null
  return String(data.sub)
}

function randomBytes(length: number) {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return bytes
}

async function derivePassword(password: string, salt: Uint8Array, iterations = ITERATIONS) {
  const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    256,
  )
  return new Uint8Array(bits)
}

function safeUsername(value: string) {
  return value.trim().toLowerCase()
}

function validUsername(username: string) {
  return /^[a-z0-9_]{3,20}$/.test(username)
}

function getBearer(req: Request) {
  const header = req.headers.get('authorization') ?? ''
  return header.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : null
}

async function currentUser(req: Request, admin: any) {
  const userId = await verifyToken(getBearer(req))
  if (!userId) return null
  const { data: profile } = await admin.from('profiles').select('*').eq('id', userId).maybeSingle()
  if (!profile || profile.is_banned) return null
  const { data: adminRow } = await admin.from('surelin_admins').select('user_id').eq('user_id', userId).maybeSingle()
  return { ...profile, is_admin: Boolean(adminRow) }
}

export default {
  fetch: withSupabase({ auth: 'publishable' }, async (req, ctx) => {
    const admin = ctx.supabaseAdmin
    const url = new URL(req.url)
    const path = url.pathname.replace(/^\/?/, '').replace(/^surelin-api\/?/, '')
    const method = req.method.toUpperCase()

    try {
      if (method === 'GET' && path === '') return json({ ok: true, name: 'Surelin API', version: 1 })

      if (method === 'POST' && path === 'auth/signup') {
        const body = await req.json()
        const username = safeUsername(String(body.username ?? ''))
        const password = String(body.password ?? '')
        const displayName = String(body.displayName ?? username).trim().slice(0, 40) || username
        if (!validUsername(username)) return json({ error: 'Username must be 3-20 characters: letters, numbers, underscores.' }, 400)
        if (password.length < 8) return json({ error: 'Password must be at least 8 characters.' }, 400)

        const { data: existing } = await admin.from('surelin_credentials').select('user_id').eq('username', username).maybeSingle()
        if (existing) return json({ error: 'That username is already taken.' }, 409)

        const userId = crypto.randomUUID()
        const salt = randomBytes(16)
        const hash = await derivePassword(password, salt)
        const saltText = b64url(salt)
        const hashText = b64url(hash)

        const { error: credError } = await admin.from('surelin_credentials').insert({
          user_id: userId,
          username,
          password_hash: hashText,
          salt: saltText,
          iterations: ITERATIONS,
        })
        if (credError) return json({ error: credError.message }, 500)

        const { error: profileError } = await admin.from('profiles').insert({
          id: userId,
          username,
          display_name: displayName,
        })
        if (profileError) {
          await admin.from('surelin_credentials').delete().eq('user_id', userId)
          return json({ error: profileError.message }, 500)
        }

        const { count } = await admin.from('surelin_admins').select('user_id', { count: 'exact', head: true })
        if ((count ?? 0) === 0) await admin.from('surelin_admins').insert({ user_id: userId })

        const token = await makeToken(userId)
        const { data: profile } = await admin.from('profiles').select('*').eq('id', userId).single()
        return json({ token, user: { ...profile, is_admin: (count ?? 0) === 0 } }, 201)
      }

      if (method === 'POST' && path === 'auth/login') {
        const body = await req.json()
        const username = safeUsername(String(body.username ?? ''))
        const password = String(body.password ?? '')
        const { data: cred } = await admin.from('surelin_credentials').select('*').eq('username', username).maybeSingle()
        if (!cred) return json({ error: 'Invalid username or password.' }, 401)
        const salt = fromB64url(cred.salt)
        const hash = await derivePassword(password, salt, Number(cred.iterations))
        if (b64url(hash) !== cred.password_hash) return json({ error: 'Invalid username or password.' }, 401)
        const { data: profile } = await admin.from('profiles').select('*').eq('id', cred.user_id).single()
        if (!profile || profile.is_banned) return json({ error: 'This account is unavailable.' }, 403)
        const { data: adminRow } = await admin.from('surelin_admins').select('user_id').eq('user_id', cred.user_id).maybeSingle()
        return json({ token: await makeToken(cred.user_id), user: { ...profile, is_admin: Boolean(adminRow) } })
      }

      const user = await currentUser(req, admin)

      if (method === 'GET' && path === 'me') {
        if (!user) return json({ error: 'Not signed in.' }, 401)
        const [{ count: followers }, { count: following }, { count: friends }] = await Promise.all([
          admin.from('follows').select('*', { count: 'exact', head: true }).eq('following_id', user.id),
          admin.from('follows').select('*', { count: 'exact', head: true }).eq('follower_id', user.id),
          admin.from('friend_requests').select('*', { count: 'exact', head: true }).or(`sender_id.eq.${user.id},receiver_id.eq.${user.id}`).eq('status', 'accepted'),
        ])
        return json({ user, stats: { followers: followers ?? 0, following: following ?? 0, friends: Math.floor((friends ?? 0) / 2) } })
      }

      if (method === 'GET' && path === 'games') {
        const mine = url.searchParams.get('mine') === '1'
        let query = admin.from('games').select('id,owner_id,name,description,visibility,published,scene,created_at,updated_at,profiles!games_owner_id_fkey(username,display_name)')
        if (mine) {
          if (!user) return json({ error: 'Not signed in.' }, 401)
          query = query.eq('owner_id', user.id)
        } else {
          query = query.eq('published', true).eq('visibility', 'public')
        }
        const { data, error } = await query.order('updated_at', { ascending: false }).limit(100)
        if (error) return json({ error: error.message }, 500)
        return json({ games: data ?? [] })
      }

      if (method === 'POST' && path === 'games') {
        if (!user) return json({ error: 'Sign in to create a game.' }, 401)
        const body = await req.json()
        const name = String(body.name ?? '').trim().slice(0, 80)
        if (!name) return json({ error: 'Game name is required.' }, 400)
        const scene = body.scene && typeof body.scene === 'object' ? body.scene : { objects: [], version: 1 }
        const { data, error } = await admin.from('games').insert({ owner_id: user.id, name, description: String(body.description ?? '').slice(0, 500), scene }).select('*').single()
        if (error) return json({ error: error.message }, 500)
        return json({ game: data }, 201)
      }

      if (method === 'PATCH' && path.startsWith('games/')) {
        if (!user) return json({ error: 'Sign in required.' }, 401)
        const id = path.split('/')[1]
        const body = await req.json()
        const patch: Record<string, unknown> = {}
        if (body.name !== undefined) patch.name = String(body.name).trim().slice(0, 80)
        if (body.description !== undefined) patch.description = String(body.description).slice(0, 500)
        if (body.visibility !== undefined) patch.visibility = body.visibility === 'private' ? 'private' : 'public'
        if (body.published !== undefined) patch.published = Boolean(body.published)
        if (body.scene !== undefined) patch.scene = body.scene
        patch.updated_at = new Date().toISOString()
        const { data, error } = await admin.from('games').update(patch).eq('id', id).eq('owner_id', user.id).select('*').single()
        if (error) return json({ error: error.message }, 500)
        return json({ game: data })
      }

      if (method === 'GET' && path.startsWith('profile/')) {
        const username = safeUsername(path.split('/')[1] ?? '')
        const { data: profile } = await admin.from('profiles').select('id,username,display_name,bio,avatar_url,sura,created_at').eq('username', username).maybeSingle()
        if (!profile) return json({ error: 'User not found.' }, 404)
        const [{ count: followers }, { count: following }, { count: games }] = await Promise.all([
          admin.from('follows').select('*', { count: 'exact', head: true }).eq('following_id', profile.id),
          admin.from('follows').select('*', { count: 'exact', head: true }).eq('follower_id', profile.id),
          admin.from('games').select('*', { count: 'exact', head: true }).eq('owner_id', profile.id),
        ])
        let relationship = null
        if (user && user.id !== profile.id) {
          const [{ data: follow }, { data: friend }] = await Promise.all([
            admin.from('follows').select('follower_id').eq('follower_id', user.id).eq('following_id', profile.id).maybeSingle(),
            admin.from('friend_requests').select('sender_id,receiver_id,status').or(`and(sender_id.eq.${user.id},receiver_id.eq.${profile.id}),and(sender_id.eq.${profile.id},receiver_id.eq.${user.id})`).order('created_at', { ascending: false }).limit(1).maybeSingle(),
          ])
          relationship = { following: Boolean(follow), friendStatus: friend?.status ?? null }
        }
        return json({ profile, stats: { followers: followers ?? 0, following: following ?? 0, games: games ?? 0 }, relationship })
      }

      if (method === 'POST' && path.startsWith('follow/')) {
        if (!user) return json({ error: 'Sign in required.' }, 401)
        const username = safeUsername(path.split('/')[1] ?? '')
        const { data: target } = await admin.from('profiles').select('id').eq('username', username).maybeSingle()
        if (!target) return json({ error: 'User not found.' }, 404)
        if (target.id === user.id) return json({ error: 'You cannot follow yourself.' }, 400)
        const { error } = await admin.from('follows').upsert({ follower_id: user.id, following_id: target.id }, { onConflict: 'follower_id,following_id' })
        if (error) return json({ error: error.message }, 500)
        return json({ following: true })
      }

      if (method === 'DELETE' && path.startsWith('follow/')) {
        if (!user) return json({ error: 'Sign in required.' }, 401)
        const username = safeUsername(path.split('/')[1] ?? '')
        const { data: target } = await admin.from('profiles').select('id').eq('username', username).maybeSingle()
        if (!target) return json({ error: 'User not found.' }, 404)
        await admin.from('follows').delete().eq('follower_id', user.id).eq('following_id', target.id)
        return json({ following: false })
      }

      if (method === 'POST' && path.startsWith('friends/')) {
        if (!user) return json({ error: 'Sign in required.' }, 401)
        const username = safeUsername(path.split('/')[1] ?? '')
        const { data: target } = await admin.from('profiles').select('id').eq('username', username).maybeSingle()
        if (!target) return json({ error: 'User not found.' }, 404)
        if (target.id === user.id) return json({ error: 'You cannot friend yourself.' }, 400)
        const { data: existing } = await admin.from('friend_requests').select('*').or(`and(sender_id.eq.${user.id},receiver_id.eq.${target.id}),and(sender_id.eq.${target.id},receiver_id.eq.${user.id})`).order('created_at', { ascending: false }).limit(1).maybeSingle()
        if (existing?.status === 'accepted') return json({ status: 'accepted' })
        if (existing?.sender_id === target.id && existing?.receiver_id === user.id && existing?.status === 'pending') {
          await admin.from('friend_requests').update({ status: 'accepted', updated_at: new Date().toISOString() }).eq('id', existing.id)
          return json({ status: 'accepted' })
        }
        const { error } = await admin.from('friend_requests').upsert({ sender_id: user.id, receiver_id: target.id, status: 'pending', updated_at: new Date().toISOString() }, { onConflict: 'sender_id,receiver_id' })
        if (error) return json({ error: error.message }, 500)
        return json({ status: 'pending' })
      }

      if (method === 'GET' && path === 'friends') {
        if (!user) return json({ error: 'Sign in required.' }, 401)
        const { data, error } = await admin.from('friend_requests').select('id,sender_id,receiver_id,status,created_at,profiles_sender:profiles!friend_requests_sender_id_fkey(username,display_name),profiles_receiver:profiles!friend_requests_receiver_id_fkey(username,display_name)').or(`sender_id.eq.${user.id},receiver_id.eq.${user.id}`).order('updated_at', { ascending: false })
        if (error) return json({ error: error.message }, 500)
        return json({ requests: data ?? [] })
      }

      if (method === 'POST' && path === 'friends/accept') {
        if (!user) return json({ error: 'Sign in required.' }, 401)
        const body = await req.json()
        const id = String(body.id ?? '')
        const { data, error } = await admin.from('friend_requests').update({ status: 'accepted', updated_at: new Date().toISOString() }).eq('id', id).eq('receiver_id', user.id).eq('status', 'pending').select('*').maybeSingle()
        if (error) return json({ error: error.message }, 500)
        if (!data) return json({ error: 'Request not found.' }, 404)
        return json({ status: 'accepted' })
      }

      if (method === 'GET' && path === 'admin/overview') {
        if (!user?.is_admin) return json({ error: 'Admin access required.' }, 403)
        const [{ count: users }, { count: games }, { count: followers }, { count: friends }] = await Promise.all([
          admin.from('profiles').select('*', { count: 'exact', head: true }),
          admin.from('games').select('*', { count: 'exact', head: true }),
          admin.from('follows').select('*', { count: 'exact', head: true }),
          admin.from('friend_requests').select('*', { count: 'exact', head: true }).eq('status', 'accepted'),
        ])
        return json({ stats: { users: users ?? 0, games: games ?? 0, follows: followers ?? 0, friendLinks: Math.floor((friends ?? 0) / 2) } })
      }

      if (method === 'GET' && path === 'admin/users') {
        if (!user?.is_admin) return json({ error: 'Admin access required.' }, 403)
        const { data, error } = await admin.from('profiles').select('id,username,display_name,sura,is_banned,created_at').order('created_at', { ascending: false }).limit(250)
        if (error) return json({ error: error.message }, 500)
        return json({ users: data ?? [] })
      }

      if (method === 'POST' && path === 'admin/ban') {
        if (!user?.is_admin) return json({ error: 'Admin access required.' }, 403)
        const body = await req.json()
        const id = String(body.userId ?? '')
        if (id === user.id) return json({ error: 'You cannot ban yourself.' }, 400)
        const { error } = await admin.from('profiles').update({ is_banned: Boolean(body.banned) }).eq('id', id)
        if (error) return json({ error: error.message }, 500)
        return json({ ok: true })
      }

      if (method === 'DELETE' && path.startsWith('admin/games/')) {
        if (!user?.is_admin) return json({ error: 'Admin access required.' }, 403)
        const id = path.split('/')[2]
        const { error } = await admin.from('games').delete().eq('id', id)
        if (error) return json({ error: error.message }, 500)
        return json({ ok: true })
      }

      return json({ error: 'Not found.' }, 404)
    } catch (error) {
      console.error(error)
      return json({ error: error instanceof Error ? error.message : 'Server error.' }, 500)
    }
  }),
}
