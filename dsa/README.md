# dsa


DSA implementation in pure Rust

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This software has **NOT** been audited and therefore most likely contains security issues!

**USE AT YOUR OWN RISK!**

### Implementation progress

- [x] Generate components
- [x] Generate keypair
- [x] Import keys
- [x] Export keys
- [x] Sign data
- [x] Verify signatures
- [ ] Test vectors

### Example

Generate a DSA keypair

```rust
let mut csprng = rand::thread_rng();
let components = Components::generate(&mut csprng, DSA_2048_256);
let private_key = PrivateKey::generate(&mut csprng, components);
let public_key = private_key.public_key();
```

Create keypair from existing components

```rust
let (p, q, g) = read_common_parameters();
let components = Components::from_components(p, q, g);

let x = read_public_component();
let public_key = PublicKey::from_components(components, x);

let y = read_private_component();
let private_key = PrivateKey::from_components(public_key, y);
```


License: Apache-2.0 OR MIT
