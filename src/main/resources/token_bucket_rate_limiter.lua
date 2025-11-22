-- token_bucket_rate_limiter.lua
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local refillTime = tonumber(ARGV[3])

local intervalPerPermit = window / limit
local burstTokens = limit
local interval = window

local bucket = redis.call('hgetall', key)
local currentTokens

if table.maxn(bucket) == 0 then
    --  check if bucket not exists, if yes, create a new one with full capacity, then grant access
    currentTokens = burstTokens
    redis.call('hset', key, 'lastRefillTime', refillTime, 'tokensRemaining', currentTokens)
elseif table.maxn(bucket) == 4 then
    -- if bucket exists, first we try to refill the token bucket
    local lastRefillTime = tonumber(bucket[2])
    local tokensRemaining = tonumber(bucket[4])

    if refillTime > lastRefillTime then
        -- if refillTime larger than lastRefillTime, refill the token buckets
        local intervalSinceLast = refillTime - lastRefillTime

        if intervalSinceLast > interval then
            currentTokens = burstTokens
            redis.call('hset', key, 'lastRefillTime', refillTime)
        else
            local grantedTokens = math.floor(intervalSinceLast / intervalPerPermit)
            if grantedTokens > 0 then
                -- adjust lastRefillTime,  shift left the refill time
                local padMillis = math.fmod(intervalSinceLast, intervalPerPermit)
                redis.call('hset', key, 'lastRefillTime', refillTime - padMillis)
            end
            currentTokens = math.min(grantedTokens + tokensRemaining, limit)
        end
    else
        -- if not, it means some other operation later than this call made the call first
        currentTokens = tokensRemaining
    end
else
    -- Handle unexpected bucket state
    currentTokens = burstTokens
    redis.call('hset', key, 'lastRefillTime', refillTime, 'tokensRemaining', currentTokens)
end

assert(currentTokens >= 0)

local allowed = 0
local remaining = 0
local retryAfter = 0

if currentTokens == 0 then
    redis.call('hset', key, 'tokensRemaining', currentTokens)
    allowed = 0
    remaining = 0
    retryAfter = intervalPerPermit
else
    redis.call('hset', key, 'tokensRemaining', currentTokens - 1)
    allowed = 1
    remaining = currentTokens - 1
end

-- Set expiration only if the key doesn't have one or it's about to expire
local currentTtl = redis.call('ttl', key)
if currentTtl == -1 then
    redis.call('expire', key, window)
end

return {allowed, remaining, retryAfter}