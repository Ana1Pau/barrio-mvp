/*
  15_directory_and_pey_status.sql
  Persiste la visibilidad del comercio y sincroniza CoDi con la verificación Pey.
*/
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF COL_LENGTH(N'biz.Comercios', N'MostrarEnDirectorio') IS NULL
  ALTER TABLE biz.Comercios ADD MostrarEnDirectorio BIT NOT NULL
    CONSTRAINT DF_biz_Comercios_MostrarEnDirectorio DEFAULT 1 WITH VALUES;
GO

CREATE OR ALTER VIEW app.PerfilPublicoComercio AS
SELECT c.ComercioId,c.NombreNegocio,c.Descripcion,c.FotoPerfilUrl,c.FotoPortadaUrl,
       c.CalificacionPromedio,c.TotalResenas,co.Nombre AS Colonia,c.DireccionLinea,
       c.Latitud,c.Longitud,c.EstaActivo,c.EstaVerificado
FROM biz.Comercios c
LEFT JOIN lkp.Colonias co ON co.ColoniaId=c.ColoniaId
WHERE c.EstaActivo=1 AND c.MostrarEnDirectorio=1;
GO

CREATE OR ALTER PROCEDURE app.sp_CrearComercioPropio
  @UsuarioId UNIQUEIDENTIFIER,
  @NombreNegocio NVARCHAR(150),
  @Descripcion NVARCHAR(500)=NULL,
  @ColoniaId INT=NULL,
  @CategoriaId INT=NULL,
  @MostrarEnDirectorio BIT=1,
  @ComercioId UNIQUEIDENTIFIER OUTPUT
AS
BEGIN
  SET NOCOUNT ON; SET XACT_ABORT ON;
  IF NOT EXISTS (SELECT 1 FROM ident.UsuarioRoles ur JOIN lkp.Roles r ON r.RolId=ur.RolId WHERE ur.UsuarioId=@UsuarioId AND r.Nombre=N'Comercio')
    THROW 50101,'El usuario no tiene rol de comercio.',1;
  IF EXISTS (SELECT 1 FROM biz.Comercios WHERE UsuarioPropietarioId=@UsuarioId)
    THROW 50102,'El usuario ya tiene un comercio.',1;
  BEGIN TRANSACTION;
  BEGIN TRY
    SET @ComercioId=NEWID();
    INSERT biz.Comercios (ComercioId,UsuarioPropietarioId,NombreNegocio,Descripcion,ColoniaId,MostrarEnDirectorio)
      VALUES (@ComercioId,@UsuarioId,@NombreNegocio,@Descripcion,@ColoniaId,@MostrarEnDirectorio);
    IF @CategoriaId IS NOT NULL INSERT biz.ComercioCategorias (ComercioId,CategoriaId) VALUES (@ComercioId,@CategoriaId);
    COMMIT TRANSACTION;
  END TRY
  BEGIN CATCH
    IF @@TRANCOUNT>0 ROLLBACK TRANSACTION;
    THROW;
  END CATCH
END;
GO

CREATE OR ALTER PROCEDURE app.sp_SincronizarMetodoPey
  @UsuarioId UNIQUEIDENTIFIER,
  @CodiStatus NVARCHAR(20)
AS
BEGIN
  SET NOCOUNT ON; SET XACT_ABORT ON;
  IF @CodiStatus NOT IN (N'PENDING',N'PROCESSING',N'ACTIVE',N'ERROR') THROW 50122,'Estado de cuenta Pey invalido.',1;
  DECLARE @ComercioId UNIQUEIDENTIFIER=(SELECT TOP(1) ComercioId FROM biz.Comercios WHERE UsuarioPropietarioId=@UsuarioId AND EstaActivo=1);
  DECLARE @MetodoPagoId TINYINT=(SELECT TOP(1) MetodoPagoId FROM lkp.MetodosPago WHERE Codigo=N'PEY_CODI');
  IF @ComercioId IS NULL OR @MetodoPagoId IS NULL THROW 50123,'No se encontró el comercio o método CoDi.',1;
  MERGE biz.ComercioMetodosPago AS target
  USING (SELECT @ComercioId AS ComercioId,@MetodoPagoId AS MetodoPagoId) AS source
    ON target.ComercioId=source.ComercioId AND target.MetodoPagoId=source.MetodoPagoId
  WHEN MATCHED THEN UPDATE SET
    EstaHabilitado=CASE WHEN @CodiStatus=N'ACTIVE' THEN 1 ELSE 0 END,
    Solicitado=1,
    EstadoConfiguracion=CASE WHEN @CodiStatus=N'ACTIVE' THEN N'DISPONIBLE' WHEN @CodiStatus=N'ERROR' THEN N'REQUIERE_PEY' ELSE N'PENDIENTE' END
  WHEN NOT MATCHED THEN INSERT (ComercioId,MetodoPagoId,EstaHabilitado,Solicitado,EstadoConfiguracion)
    VALUES (@ComercioId,@MetodoPagoId,CASE WHEN @CodiStatus=N'ACTIVE' THEN 1 ELSE 0 END,1,
      CASE WHEN @CodiStatus=N'ACTIVE' THEN N'DISPONIBLE' WHEN @CodiStatus=N'ERROR' THEN N'REQUIERE_PEY' ELSE N'PENDIENTE' END);
END;
GO

GRANT EXECUTE ON OBJECT::app.sp_CrearComercioPropio TO role_app_api;
GRANT EXECUTE ON OBJECT::app.sp_SincronizarMetodoPey TO role_app_api;
GO
