# Changelog

Entries are listed in reverse chronological order.

## 2.1.1

* Adds the "crypto" tag to crate metadata.
* New shorter, more efficient ct_eq() for integers, contributed by Thomas Pornin.

## 2.1.0

* Adds a new `CtOption<T>` which acts as a constant-time `Option<T>`
  (thanks to @ebfull for the implementation).
* `Choice` now itself implements `ConditionallySelectable`.

## 2.0.0

* Stable version with traits reworked from 1.0.0 to interact better
  with the orphan rules.
