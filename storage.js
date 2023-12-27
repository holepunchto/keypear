try {
  module.exports = require('./fs-storage')
} catch {
  module.exports = require('./no-storage')
}
