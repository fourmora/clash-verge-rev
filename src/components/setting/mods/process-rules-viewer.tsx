import { AddRounded, SearchRounded } from '@mui/icons-material'
import {
  Box,
  Chip,
  CircularProgress,
  Divider,
  IconButton,
  List,
  ListItem,
  ListItemText,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { useLockFn } from 'ahooks'
import { forwardRef, useImperativeHandle, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { BaseDialog } from '@/components/base'
import { useVerge } from '@/hooks/use-verge'
import { listSystemProcesses, patchVergeConfig } from '@/services/cmds'
import { showNotice } from '@/services/notice-service'

interface ProcessRulesViewerRef {
  open: () => void
  close: () => void
}

export const ProcessRulesViewer = forwardRef<ProcessRulesViewerRef>(
  (_, ref) => {
    const { t } = useTranslation()
    const { verge, mutateVerge } = useVerge()

    const [open, setOpen] = useState(false)
    const [processes, setProcesses] = useState<string[]>([])
    const [target, setTarget] = useState('')
    const [manualName, setManualName] = useState('')
    const [systemList, setSystemList] = useState<string[]>([])
    const [search, setSearch] = useState('')
    const [loadingSystem, setLoadingSystem] = useState(false)

    useImperativeHandle(ref, () => ({
      open: () => {
        setProcesses(verge?.process_proxy_list ?? [])
        setTarget(verge?.process_proxy_target ?? '')
        setSystemList([])
        setSearch('')
        setManualName('')
        setOpen(true)
      },
      close: () => setOpen(false),
    }))

    const addProcess = (name: string) => {
      const trimmed = name.trim()
      if (!trimmed) {
        showNotice.error(t('settings.modals.appProxy.messages.emptyName'))
        return
      }
      if (processes.some((p) => p.toLowerCase() === trimmed.toLowerCase())) {
        showNotice.error(t('settings.modals.appProxy.messages.duplicate'))
        return
      }
      setProcesses((prev) => [...prev, trimmed])
    }

    const removeProcess = (name: string) =>
      setProcesses((prev) => prev.filter((p) => p !== name))

    const loadSystemProcesses = useLockFn(async () => {
      setLoadingSystem(true)
      try {
        const list = await listSystemProcesses()
        setSystemList(list)
      } catch (err) {
        showNotice.error(err)
      } finally {
        setLoadingSystem(false)
      }
    })

    const onSave = useLockFn(async () => {
      try {
        await patchVergeConfig({
          process_proxy_list: processes,
          process_proxy_target: target.trim() || null,
        })
        mutateVerge()
        setOpen(false)
        showNotice.success(t('settings.modals.appProxy.messages.saved'))
      } catch (err) {
        showNotice.error(err)
      }
    })

    const filteredSystem = systemList.filter(
      (name) => !search || name.toLowerCase().includes(search.toLowerCase()),
    )

    return (
      <BaseDialog
        open={open}
        title={t('settings.modals.appProxy.title')}
        contentSx={{ width: 460 }}
        okBtn={t('shared.actions.save')}
        cancelBtn={t('shared.actions.cancel')}
        onClose={() => setOpen(false)}
        onCancel={() => setOpen(false)}
        onOk={onSave}
      >
        <Stack spacing={2}>
          <Box>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              {t('settings.modals.appProxy.selected')}
            </Typography>
            {processes.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {t('settings.modals.appProxy.selectedEmpty')}
              </Typography>
            ) : (
              <Stack direction="row" spacing={0.5} useFlexGap flexWrap="wrap">
                {processes.map((name) => (
                  <Chip
                    key={name}
                    size="small"
                    label={name}
                    onDelete={() => removeProcess(name)}
                    sx={{ mb: 0.5 }}
                  />
                ))}
              </Stack>
            )}
          </Box>

          <Divider />

          <Stack direction="row" spacing={1} alignItems="center">
            <TextField
              size="small"
              fullWidth
              label={t('settings.modals.appProxy.manualLabel')}
              placeholder={t('settings.modals.appProxy.manualPlaceholder')}
              value={manualName}
              onChange={(e) => setManualName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  addProcess(manualName)
                  setManualName('')
                }
              }}
            />
            <IconButton
              size="small"
              onClick={() => {
                addProcess(manualName)
                setManualName('')
              }}
            >
              <AddRounded />
            </IconButton>
          </Stack>

          <TextField
            size="small"
            fullWidth
            label={t('settings.modals.appProxy.targetLabel')}
            helperText={t('settings.modals.appProxy.targetHint')}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />

          <Divider />

          <Box>
            <Stack
              direction="row"
              spacing={1}
              alignItems="center"
              sx={{ mb: 1 }}
            >
              <Typography variant="subtitle2" sx={{ flex: 1 }}>
                {t('settings.modals.appProxy.systemLabel')}
              </Typography>
              <TextField
                size="small"
                sx={{ width: 180 }}
                placeholder={t('settings.modals.appProxy.searchPlaceholder')}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                slotProps={{
                  input: {
                    startAdornment: (
                      <SearchRounded
                        fontSize="small"
                        sx={{ mr: 0.5, opacity: 0.6 }}
                      />
                    ),
                  },
                }}
              />
              <IconButton
                size="small"
                onClick={loadSystemProcesses}
                disabled={loadingSystem}
              >
                {loadingSystem ? (
                  <CircularProgress size={18} />
                ) : (
                  <SearchRounded fontSize="small" />
                )}
              </IconButton>
            </Stack>
            <List
              dense
              sx={{
                maxHeight: 220,
                overflow: 'auto',
                border: 1,
                borderColor: 'divider',
                borderRadius: 1,
              }}
            >
              {systemList.length === 0 ? (
                <ListItem>
                  <ListItemText
                    primary={t('settings.modals.appProxy.empty')}
                    slotProps={{
                      primary: {
                        sx: { fontSize: 12, color: 'text.secondary' },
                      },
                    }}
                  />
                </ListItem>
              ) : (
                filteredSystem.map((name) => (
                  <ListItem
                    key={name}
                    sx={{ cursor: 'pointer' }}
                    onClick={() => addProcess(name)}
                  >
                    <ListItemText
                      primary={name}
                      slotProps={{ primary: { sx: { fontSize: 12 } } }}
                    />
                  </ListItem>
                ))
              )}
            </List>
          </Box>
        </Stack>
      </BaseDialog>
    )
  },
)
