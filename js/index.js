Module = {
  ENVIRONMENT: "NODE"
}

var rs = require('./rs.ec')

var ReedSolomon = function ReedSolomon(dataShards, parityShards) {
  dataShards = dataShards | 0
  parityShards = parityShards | 0
  if(!(this instanceof ReedSolomon)) {
    return new ReedSolomon(dataShards, parityShards)
  }
  rs.ccall('fec_init', null)
  this._rs = rs.ccall('reed_solomon_new',
    'number',
    ['number', 'number'],
    [dataShards, parityShards])
  this._ds = dataShards
  this._ps = parityShards
  return this
}

ReedSolomon.prototype.encode = function encode(data) {
  if(!(data instanceof Uint8Array)) {
    throw new Error('Expected a Uint8Array or Buffer object for data')
  }
  var bs = data.length / this._ds
  var result = new Uint8Array(this._ps * bs)
  var err = rs.ccall('reed_solomon_encode',
    'number',
    ['array', 'array', 'number', 'number'],
    [data, result, bs, data.length])
  if (err !== 0) {
    throw new Error(`Received error ${err} from libstorj`)
  }
  return result
}

ReedSolomon.prototype.cleanup = function cleanup() {
  return rs.ccall('reed_solomon_release',
    null,
    ['number'],
    [this._rs])
}

module.exports = ReedSolomon
