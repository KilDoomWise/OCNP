local component = require("component")
local computer = require("computer")
local serialization = require("serialization")

local OCNP = {}
OCNP.VERSION = "1.1"
OCNP.DELIMITER = "|"
OCNP.MAX_PACKET_SIZE = 8192
OCNP.HEADER_OVERHEAD = 150
OCNP.CHUNK_SIZE = 7000
OCNP.DEFAULT_TTL = 16

local uidCounter = 0
local lastUIDTime = 0

OCNP.TYPE = {
  DATA = "D",
  ACK = "A",
  CHUNK = "C",
  CHUNK_REQ = "R",
  PING = "P",
  ERROR = "E",
  SYN = "S",
  FIN = "F",
  ORS = "O"
}

local function calculateHash(data)
  local hash = 0
  for i = 1, #data do
    hash = (hash + string.byte(data, i)) % 65536
  end
  return string.format("%04X", hash)
end

function OCNP.generateUID(sender, seq, ts)
  uidCounter = (uidCounter + 1) % 1000000
  
  if ts ~= lastUIDTime then
    lastUIDTime = ts
    uidCounter = 0
  end
  
  local base = sender .. ":" .. tostring(seq) .. ":" .. tostring(ts) .. ":" .. tostring(uidCounter)
  local hash = calculateHash(base)
  
  return string.format("%08X", (tonumber(hash, 16) * 256 + uidCounter) % 4294967296)
end

-- ========================================
-- НОВОЕ: Сериализация таблицы пакета в строку
-- Принимает parsed таблицу, возвращает строку
-- ========================================
function OCNP.serialize(parsed)
  if not parsed then
    return nil, "No packet to serialize"
  end
  
  local payload = parsed.payload or ""
  
  -- Если payload - таблица, сериализуем
  if type(payload) == "table" then
    payload = serialization.serialize(payload)
  end
  
  -- Собираем базу для хеша
  local base = OCNP.VERSION .. OCNP.DELIMITER ..
               parsed.type .. OCNP.DELIMITER ..
               parsed.src .. OCNP.DELIMITER ..
               parsed.dst .. OCNP.DELIMITER ..
               tostring(parsed.seq) .. OCNP.DELIMITER ..
               parsed.uid .. OCNP.DELIMITER ..
               tostring(parsed.ts) .. OCNP.DELIMITER ..
               tostring(parsed.ttl)
  
  -- ПЕРЕСЧИТЫВАЕМ хеш с новыми данными
  local hash = calculateHash(base .. payload)
  
  local packet = base .. OCNP.DELIMITER .. hash .. OCNP.DELIMITER .. payload
  
  return packet
end

function OCNP.createPacket(sender, receiver, ptype, payload, seq, uid, ts, ttl)
  seq = seq or 0
  ts = ts or math.floor(computer.uptime())
  ttl = ttl or OCNP.DEFAULT_TTL
  payload = payload or ""
  
  if type(payload) == "table" then
    payload = serialization.serialize(payload)
  end
  
  if not uid then
    uid = OCNP.generateUID(sender, seq, ts)
  end
  
  local base = OCNP.VERSION .. OCNP.DELIMITER ..
               ptype .. OCNP.DELIMITER ..
               sender .. OCNP.DELIMITER ..
               receiver .. OCNP.DELIMITER ..
               tostring(seq) .. OCNP.DELIMITER ..
               uid .. OCNP.DELIMITER ..
               tostring(ts) .. OCNP.DELIMITER ..
               tostring(ttl)
  
  local hash = calculateHash(base .. payload)
  
  local packet = base .. OCNP.DELIMITER .. hash .. OCNP.DELIMITER .. payload
  
  return packet
end

function OCNP.parsePacket(packet)
  if not packet or packet == "" then
    return nil, "Empty packet"
  end
  
  -- Защита: проверяем что это строка
  if type(packet) ~= "string" then
    return nil, "Packet must be a string"
  end
  
  local parts = {}
  local start = 1
  
  for i = 1, 9 do
    local pos = string.find(packet, OCNP.DELIMITER, start, true)
    if not pos then
      return nil, "Invalid packet format"
    end
    table.insert(parts, string.sub(packet, start, pos - 1))
    start = pos + 1
  end
  
  local payload = string.sub(packet, start)
  
  local parsed = {
    version = parts[1],
    type = parts[2],
    src = parts[3],
    dst = parts[4],
    seq = tonumber(parts[5]),
    uid = parts[6],
    ts = tonumber(parts[7]),
    ttl = tonumber(parts[8]),
    hash = parts[9],
    payload = payload,
    isPayloadTable = false  -- НОВОЕ: флаг типа payload
  }
  
  if parsed.version ~= OCNP.VERSION then
    return nil, "Incompatible protocol version"
  end
  
  local base = parsed.version .. OCNP.DELIMITER ..
               parsed.type .. OCNP.DELIMITER ..
               parsed.src .. OCNP.DELIMITER ..
               parsed.dst .. OCNP.DELIMITER ..
               tostring(parsed.seq) .. OCNP.DELIMITER ..
               parsed.uid .. OCNP.DELIMITER ..
               tostring(parsed.ts) .. OCNP.DELIMITER ..
               tostring(parsed.ttl)
  
  local expectedHash = calculateHash(base .. payload)
  
  if parsed.hash ~= expectedHash then
    return nil, "Hash mismatch - packet corrupted"
  end
  
  -- УЛУЧШЕНО: Безопасная десериализация payload
  if payload ~= "" and string.sub(payload, 1, 1) == "{" then
    local success, data = pcall(serialization.unserialize, payload)
    if success and type(data) == "table" then
      parsed.payload = data
      parsed.isPayloadTable = true
    end
    -- Если не получилось - оставляем как строку
  end
  
  return parsed
end

-- ========================================
-- ИЗМЕНЕНО: Декремент TTL работает с таблицей
-- Принимает таблицу, возвращает ту же таблицу (или nil + ошибка)
-- ========================================
function OCNP.decrementTTL(parsed)
  if not parsed then
    return nil, "No packet"
  end
  
  if parsed.ttl <= 0 then
    return nil, "TTL expired"
  end
  
  -- Просто уменьшаем TTL в таблице
  parsed.ttl = parsed.ttl - 1
  
  return parsed
end

-- Старая функция для совместимости (если нужна строка сразу)
function OCNP.decrementTTLToString(parsed)
  local result, err = OCNP.decrementTTL(parsed)
  if not result then
    return nil, err
  end
  return OCNP.serialize(result)
end

function OCNP.createAck(sender, receiver, seq, uid, ts, ttl)
  return OCNP.createPacket(sender, receiver, OCNP.TYPE.ACK, "OK", seq, uid, ts, ttl)
end

function OCNP.createError(sender, receiver, code, reason, info, seq)
  local payload = {
    code = code,
    reason = reason,
    info = info or {}
  }
  return OCNP.createPacket(sender, receiver, OCNP.TYPE.ERROR, payload, seq)
end

function OCNP.splitIntoChunks(data, chunkSize)
  chunkSize = chunkSize or OCNP.CHUNK_SIZE
  local chunks = {}
  local totalSize = #data
  local numChunks = math.ceil(totalSize / chunkSize)
  
  for i = 0, numChunks - 1 do
    local start = i * chunkSize + 1
    local finish = math.min((i + 1) * chunkSize, totalSize)
    chunks[i] = string.sub(data, start, finish)
  end
  
  return chunks, numChunks, totalSize
end

function OCNP.createChunkPacket(sender, receiver, chunkId, totalChunks, totalSize, fileHash, chunkData, seq, uid, ts, ttl)
  local payload = tostring(chunkId) .. ":" ..
                  tostring(totalChunks) .. ":" ..
                  tostring(totalSize) .. ":" ..
                  fileHash .. ":" ..
                  chunkData
  
  return OCNP.createPacket(sender, receiver, OCNP.TYPE.CHUNK, payload, seq, uid, ts, ttl)
end

function OCNP.parseChunkPacket(parsed)
  if parsed.type ~= OCNP.TYPE.CHUNK then
    return nil, "Not a chunk packet"
  end
  
  local payload = parsed.payload
  if type(payload) ~= "string" then
    return nil, "Chunk payload must be string"
  end
  
  local chunkId, totalChunks, totalSize, fileHash, data = string.match(
    payload,
    "(%d+):(%d+):(%d+):([^:]+):(.*)$"
  )
  
  if not chunkId then
    return nil, "Invalid chunk format"
  end
  
  return {
    chunkId = tonumber(chunkId),
    totalChunks = tonumber(totalChunks),
    totalSize = tonumber(totalSize),
    fileHash = fileHash,
    data = data,
    sender = parsed.src,
    receiver = parsed.dst,
    seq = parsed.seq,
    uid = parsed.uid,
    ts = parsed.ts,
    ttl = parsed.ttl
  }
end

function OCNP.send(modem, port, sender, receiver, ptype, payload, seq, uid, ts, ttl)
  local packet = OCNP.createPacket(sender, receiver, ptype, payload, seq, uid, ts, ttl)
  modem.broadcast(port, packet)
  return packet
end

function OCNP.sendTo(modem, targetMAC, port, sender, receiver, ptype, payload, seq, uid, ts, ttl)
  local packet = OCNP.createPacket(sender, receiver, ptype, payload, seq, uid, ts, ttl)
  if modem.send then
    modem.send(targetMAC, port, packet) 
  else
    modem.broadcast(port, packet)
  end
  return packet
end

function OCNP.receive(eventData)
  if eventData[1] ~= "modem_message" then
    return nil, "Not a modem_message event"
  end
  
  local packet = eventData[6]
  return OCNP.parsePacket(packet)
end

-- ========================================
-- Вспомогательные функции для работы с parsed
-- ========================================

-- Безопасное получение поля из payload
function OCNP.getPayloadField(parsed, fieldName, default)
  if parsed.isPayloadTable and type(parsed.payload) == "table" then
    return parsed.payload[fieldName] or default
  end
  return default
end

-- Безопасная установка поля в payload
function OCNP.setPayloadField(parsed, fieldName, value)
  if not parsed.isPayloadTable then
    -- Преобразуем payload в таблицу если нужно
    parsed.payload = {}
    parsed.isPayloadTable = true
  end
  parsed.payload[fieldName] = value
end

-- Клонирование parsed для безопасности
function OCNP.cloneParsed(parsed)
  local clone = {
    version = parsed.version,
    type = parsed.type,
    src = parsed.src,
    dst = parsed.dst,
    seq = parsed.seq,
    uid = parsed.uid,
    ts = parsed.ts,
    ttl = parsed.ttl,
    hash = parsed.hash,
    isPayloadTable = parsed.isPayloadTable
  }
  
  if parsed.isPayloadTable and type(parsed.payload) == "table" then
    clone.payload = {}
    for k, v in pairs(parsed.payload) do
      clone.payload[k] = v
    end
  else
    clone.payload = parsed.payload
  end
  
  return clone
end

-- ========================================
-- ChunkSender и ChunkReceiver (без изменений)
-- ========================================

OCNP.ChunkSender = {}
OCNP.ChunkSender.__index = OCNP.ChunkSender

function OCNP.ChunkSender.new(modem, port, sender, receiver, data, chunkSize)
  local self = setmetatable({}, OCNP.ChunkSender)
  
  self.modem = modem
  self.port = port
  self.sender = sender
  self.receiver = receiver
  self.data = data
  self.fileHash = calculateHash(data)
  self.chunks, self.totalChunks, self.totalSize = OCNP.splitIntoChunks(data, chunkSize)
  self.ackReceived = {}
  self.currentSeq = 0
  
  return self
end

function OCNP.ChunkSender:sendChunk(chunkId)
  if not self.chunks[chunkId] then
    return false, "Chunk does not exist"
  end
  
  local packet = OCNP.createChunkPacket(
    self.sender,
    self.receiver,
    chunkId,
    self.totalChunks,
    self.totalSize,
    self.fileHash,
    self.chunks[chunkId],
    self.currentSeq
  )
  
  self.modem.broadcast(self.port, packet)
  self.currentSeq = self.currentSeq + 1
  
  return true
end

function OCNP.ChunkSender:sendAll()
  for i = 0, self.totalChunks - 1 do
    self:sendChunk(i)
    os.sleep(0.05)
  end
end

function OCNP.ChunkSender:getProgress()
  local received = 0
  for _ in pairs(self.ackReceived) do
    received = received + 1
  end
  return received, self.totalChunks
end

OCNP.ChunkReceiver = {}
OCNP.ChunkReceiver.__index = OCNP.ChunkReceiver

function OCNP.ChunkReceiver.new(sender, receiver)
  local self = setmetatable({}, OCNP.ChunkReceiver)
  
  self.sender = sender
  self.receiver = receiver
  self.chunks = {}
  self.totalChunks = nil
  self.totalSize = nil
  self.fileHash = nil
  self.receivedCount = 0
  
  return self
end

function OCNP.ChunkReceiver:processChunk(chunkInfo)
  if not self.totalChunks then
    self.totalChunks = chunkInfo.totalChunks
    self.totalSize = chunkInfo.totalSize
    self.fileHash = chunkInfo.fileHash
  end
  
  if chunkInfo.totalChunks ~= self.totalChunks or chunkInfo.fileHash ~= self.fileHash then
    return false, "Incompatible chunk metadata"
  end
  
  if not self.chunks[chunkInfo.chunkId] then
    self.chunks[chunkInfo.chunkId] = chunkInfo.data
    self.receivedCount = self.receivedCount + 1
  end
  
  return true
end

function OCNP.ChunkReceiver:isComplete()
  return self.receivedCount == self.totalChunks
end

function OCNP.ChunkReceiver:getMissingChunks()
  local missing = {}
  for i = 0, (self.totalChunks or 0) - 1 do
    if not self.chunks[i] then
      table.insert(missing, i)
    end
  end
  return missing
end

function OCNP.ChunkReceiver:assemble()
  if not self:isComplete() then
    return nil, "Not all chunks received"
  end
  
  local result = {}
  for i = 0, self.totalChunks - 1 do
    table.insert(result, self.chunks[i])
  end
  
  local assembled = table.concat(result)
  
  if calculateHash(assembled) ~= self.fileHash then
    return nil, "File hash mismatch"
  end
  
  return assembled
end

function OCNP.ChunkReceiver:getProgress()
  return self.receivedCount, self.totalChunks or 0
end

return OCNP
