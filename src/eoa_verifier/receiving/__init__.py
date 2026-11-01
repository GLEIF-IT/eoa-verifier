"""Finite CESR HTTP intake and durable replay of KERIpy-accepted IPEX Grant notices.

HTTP 204 acknowledges queued bytes only. KERIpy validates evidence; replay
creates one durable initial-verification obligation at a time.
"""
