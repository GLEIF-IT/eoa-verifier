"""Typed LMDB records, detached reads and explicit atomic feature transitions.

Services prepare valid outcomes before entering writers. This package owns no
credential policy, scheduling, HTTP or RPC effects; KERI evidence stores remain
separate from the application environment.
"""
